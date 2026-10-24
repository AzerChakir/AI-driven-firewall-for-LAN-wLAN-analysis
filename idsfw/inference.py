"""Loads the trained Keras model + preprocessing artifacts and scores flows.

The model directory is expected to contain the artifacts produced by the
training notebook:

* ``ids_model.keras``     - binary classifier (BENIGN / ATTACK)
* ``preprocessing.pkl``   - ``{"imputer": SimpleImputer(median),
                              "scaler": StandardScaler(),
                              "selected_features": [...30 names...]}``
* ``metadata.json``       - threshold, input feature count, label mapping

Three backends are supported, chosen automatically in this order:

1. ``tf``      - TensorFlow / Keras (full-fidelity, used on the Pi);
2. ``tflite``  - ``ids_model.tflite`` via ``tensorflow.lite`` or
                 ``tflite_runtime`` (optional, lower memory);
3. ``mock``    - deterministic stand-in used for development on machines
                 without TensorFlow. It is clearly reported as ``mock`` in the
                 dashboard and must never be used for real blocking decisions.
"""

from __future__ import annotations

import json
import logging
import math
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import numpy as np

log = logging.getLogger("idsfw.inference")


@dataclass(slots=True)
class Prediction:
    score: float  # P(ATTACK)
    label: str
    threshold: float


class ModelArtifacts:
    """Everything needed to reproduce training-time preprocessing."""

    def __init__(self, model_dir: str | Path) -> None:
        self.dir = Path(model_dir)
        if not self.dir.is_dir():
            raise FileNotFoundError(f"model directory not found: {self.dir}")

        meta_path = self.dir / "metadata.json"
        self.metadata: dict[str, Any] = {}
        if meta_path.exists():
            self.metadata = json.loads(meta_path.read_text())
        else:
            log.warning("metadata.json missing in %s", self.dir)

        prep_name = self.metadata.get("preprocessing_artifact", "preprocessing.pkl")
        model_name = self.metadata.get("model_artifact", "ids_model.keras")
        self.preprocessing_path = self.dir / prep_name
        self.model_path = self.dir / model_name
        self.tflite_path = self.dir / (Path(model_name).stem + ".tflite")

        if not self.preprocessing_path.exists():
            raise FileNotFoundError(f"preprocessing artifact not found: {self.preprocessing_path}")
        if not self.model_path.exists() and not self.tflite_path.exists():
            raise FileNotFoundError(f"no model artifact ({model_name} / .tflite) in {self.dir}")

        prep = self._load_preprocessing(self.preprocessing_path)
        self.imputer = prep.get("imputer")
        self.scaler = prep.get("scaler")
        self.selected_features: list[str] = list(prep["selected_features"])
        self.impute_scope = prep.get("impute_scope", "selected")
        if not self.selected_features:
            raise ValueError("preprocessing.pkl defines no selected_features")

        n_features = int(self.metadata.get("input_features", len(self.selected_features)))
        if n_features != len(self.selected_features):
            log.warning(
                "metadata input_features=%s but selected_features has %s entries",
                n_features,
                len(self.selected_features),
            )

        threshold = self.metadata.get("classification_threshold", 0.5)
        self.threshold = float(threshold)
        output = self.metadata.get("output") or {"0": "BENIGN", "1": "ATTACK"}
        self.labels = [output.get("0", "BENIGN"), output.get("1", "ATTACK")]

    @staticmethod
    def _load_preprocessing(path: Path) -> dict:
        """Loads the pickle either directly or through joblib.

        ``preprocessing.pkl`` was written with ``joblib.dump``; plain
        ``pickle.load`` cannot always replay it (joblib's custom memoisation is
        required), so joblib is tried first.
        """
        try:
            import joblib

            return joblib.load(path)
        except Exception:  # pragma: no cover - fallback path
            import pickle

            with path.open("rb") as fh:
                return pickle.load(fh)


class Predictor:
    def __init__(self, model_dir: str | Path, threshold: float | None = None) -> None:
        self.artifacts = ModelArtifacts(model_dir)
        self.features = self.artifacts.selected_features
        self.threshold = float(threshold) if threshold is not None else self.artifacts.threshold
        self.rows_scored = 0
        self.attacks = 0
        self._mock = None
        self.backend, self.model = self._load_model()

    # -- setup ---------------------------------------------------------------
    def _load_model(self):
        try:
            import tensorflow as tf  # noqa: PLC0415

            tf.get_logger().setLevel("ERROR")
            model = tf.keras.models.load_model(self.artifacts.model_path, compile=False)
            log.info("loaded TensorFlow/Keras model from %s", self.artifacts.model_path)
            return "tf", model
        except ImportError:
            log.warning("TensorFlow not available, trying tflite backend")
        except Exception as exc:  # model file problem
            log.error("failed to load Keras model (%s), trying tflite", exc)

        if self.artifacts.tflite_path.exists():
            try:
                interpreter = self._load_tflite(self.artifacts.tflite_path)
                log.info("loaded TFLite model from %s", self.artifacts.tflite_path)
                return "tflite", interpreter
            except Exception as exc:
                log.error("failed to load TFLite model: %s", exc)

        log.warning(
            "no usable model backend found - falling back to the MOCK predictor. "
            "Detections are synthetic and blocking is discouraged."
        )
        self._mock = np.random.default_rng(20261018)
        return "mock", None

    @staticmethod
    def _load_tflite(path: Path):
        try:
            from tensorflow.lite.python.interpreter import Interpreter  # noqa: PLC0415
        except Exception:
            from tflite_runtime.interpreter import Interpreter  # noqa: PLC0415

        interpreter = Interpreter(model_path=str(path))
        interpreter.allocate_tensors()
        return interpreter

    def model_info(self) -> dict:
        model_file = (
            self.artifacts.tflite_path.name
            if self.backend == "tflite"
            else self.artifacts.model_path.name
        )
        return {
            "dir": str(self.artifacts.dir),
            "backend": self.backend,
            "model_file": model_file,
            "features": len(self.features),
            "threshold": self.threshold,
            "labels": self.artifacts.labels,
            "trained_on": self.artifacts.metadata.get("training_epochs_completed"),
            "created_utc": self.artifacts.metadata.get("created_utc"),
            "rows_scored": self.rows_scored,
            "attacks": self.attacks,
        }

    # -- inference -----------------------------------------------------------
    def _matrix(self, rows: Iterable[dict]) -> np.ndarray:
        matrix = np.empty((0, len(self.features)), dtype=np.float64)
        values = []
        for row in rows:
            values.append([row.get(name, float("nan")) for name in self.features])
        matrix = np.asarray(values, dtype=np.float64)
        if matrix.size == 0:
            return matrix.reshape(0, len(self.features))
        # sklearn imputers reject +/-inf; treat it as missing like NaN
        matrix[~np.isfinite(matrix)] = np.nan
        return matrix

    def predict_rows(self, rows: list[dict]) -> list[Prediction]:
        if not rows:
            return []
        matrix = self._matrix(rows)
        matrix = self._preprocess(matrix)

        if self.backend == "tf":
            scores = self.model.predict(matrix, verbose=0).reshape(-1)
        elif self.backend == "tflite":
            scores = self._predict_tflite(matrix)
        else:
            scores = self._predict_mock(matrix)

        results: list[Prediction] = []
        for score in scores:
            score = float(min(max(score, 0.0), 1.0))
            attack = score >= self.threshold
            results.append(
                Prediction(score=score, label="ATTACK" if attack else "BENIGN", threshold=self.threshold)
            )
            self.rows_scored += 1
            if attack:
                self.attacks += 1
        return results

    def _predict_tflite(self, matrix: np.ndarray) -> np.ndarray:
        interpreter = self.model
        input_details = interpreter.get_input_details()[0]
        output_details = interpreter.get_output_details()[0]
        out = np.empty(len(matrix), dtype=np.float64)
        for idx, row in enumerate(matrix):
            data = row.astype(input_details["dtype"]).reshape(input_details["shape"])
            interpreter.set_tensor(input_details["index"], data)
            interpreter.invoke()
            value = interpreter.get_tensor(output_details["index"]).reshape(-1)[0]
            out[idx] = value
        return out

    def _preprocess(self, matrix: np.ndarray) -> np.ndarray:
        """Applies imputer + scaler, with a version-proof fallback.

        ``preprocessing.pkl`` was written by scikit-learn 1.6.1.  When the
        installed scikit-learn is much newer, calling ``transform`` can fail
        (private attributes are renamed between releases).  In that case the
        learned statistics are applied directly - the results are identical.

        sklearn >= 1.2 warns when a transformer fitted with a DataFrame
        receives a plain ndarray.  We suppress that specific warning because
        we intentionally pass raw arrays to avoid a pandas dependency.
        """
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message="X does not have valid feature names",
                    category=UserWarning,
                )
                if self.artifacts.imputer is not None:
                    matrix = self.artifacts.imputer.transform(matrix)
                if self.artifacts.scaler is not None:
                    matrix = self.artifacts.scaler.transform(matrix)
            return matrix
        except Exception as exc:  # pragma: no cover - depends on local sklearn
            log.warning(
                "sklearn preprocessing transform failed (%s); "
                "falling back to attribute-based imputation/scaling",
                exc,
            )
            return self._preprocess_manual(matrix)

    def _preprocess_manual(self, matrix: np.ndarray) -> np.ndarray:
        imputer = self.artifacts.imputer
        if imputer is not None:
            statistics = getattr(imputer, "statistics_", None)
            missing = getattr(imputer, "missing_values", np.nan)
            if statistics is not None and np.isnan(missing):
                statistics = np.where(np.isnan(statistics), 0.0, statistics)
            if statistics is not None:
                mask = ~np.isfinite(matrix) if isinstance(missing, float) and np.isnan(missing) else matrix == missing
                matrix = matrix.copy()
                matrix[mask] = np.take(statistics, np.where(mask)[1])
            else:
                log.error("imputer has no statistics_ - cannot impute missing values")

        scaler = self.artifacts.scaler
        if scaler is not None:
            mean = getattr(scaler, "mean_", None)
            scale = getattr(scaler, "scale_", None)
            if mean is not None and scale is not None:
                scale = np.where(scale == 0, 1.0, scale)
                matrix = (matrix - mean) / scale
            else:
                log.error("scaler has no mean_/scale_ - skipping standardisation")
        return matrix

    def _predict_mock(self, matrix: np.ndarray) -> np.ndarray:
        """Deterministic pseudo-scores so the pipeline can be exercised offline."""
        if self._mock is None:
            self._mock = np.random.default_rng(20261018)
        # a handful of features that differ strongly between benign and attack
        # traffic in the CICIDS family (synthetic weights, NOT the real model)
        weights = self._mock.normal(0.0, 0.35, size=len(self.features))
        logits = matrix @ weights / max(1.0, math.sqrt(len(self.features)))
        return 1.0 / (1.0 + np.exp(-logits))
