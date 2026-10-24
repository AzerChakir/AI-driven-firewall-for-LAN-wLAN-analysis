#!/usr/bin/env python3
"""
CIC-IDS2017 Training Pipeline
==============================
Trains an improved binary classifier on the CIC-IDS2017 dataset that
better covers Web attacks (XSS, SQLi), DoS, DDoS, PortScan, Brute-Force,
Botnet, Heartbleed, and Infiltration.

Run on your PC (not the Pi), then transfer model_save/ to the Pi.

Usage:
    # Kaggle CSV format (most common):
    python training/train_cicids2017.py --data-dir /path/to/cicids2017/

    # With explicit output directory:
    python training/train_cicids2017.py --data-dir /data/cic/ --out-dir model_save_v2/

    # Quick smoke-test with 20% of data:
    python training/train_cicids2017.py --data-dir /data/cic/ --sample 0.2

Requirements (on your PC):
    pip install tensorflow scikit-learn imbalanced-learn joblib numpy pandas matplotlib seaborn
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore", category=UserWarning)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("train")

# ---------------------------------------------------------------------------
# CIC-IDS2017 column name variants (the Kaggle CSV has spaces, official has mixed)
# ---------------------------------------------------------------------------
COL_ALIASES: dict[str, str] = {
    # Kaggle variant → canonical
    " Flow ID": "Flow ID",
    " Source IP": "Source IP",
    " Source Port": "Source Port",
    " Destination IP": "Destination IP",
    " Destination Port": "Destination Port",
    " Protocol": "Protocol",
    " Timestamp": "Timestamp",
    " Flow Duration": "Flow Duration",
    " Total Fwd Packets": "Total Fwd Packets",
    " Total Backward Packets": "Total Backward Packets",
    " Total Length of Fwd Packets": "Total Length of Fwd Packets",
    " Total Length of Bwd Packets": "Total Length of Bwd Packets",
    " Fwd Packet Length Max": "Fwd Packet Length Max",
    " Fwd Packet Length Min": "Fwd Packet Length Min",
    " Fwd Packet Length Mean": "Fwd Packet Length Mean",
    " Fwd Packet Length Std": "Fwd Packet Length Std",
    "Bwd Packet Length Max": "Bwd Packet Length Max",
    "Bwd Packet Length Min": "Bwd Packet Length Min",
    "Bwd Packet Length Mean": "Bwd Packet Length Mean",
    "Bwd Packet Length Std": "Bwd Packet Length Std",
    "Flow Bytes/s": "Flow Bytes/s",
    "Flow Packets/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Total": "Fwd IAT Total",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Total": "Bwd IAT Total",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags",
    "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags",
    "Bwd URG Flags": "Bwd URG Flags",
    "Fwd Header Length": "Fwd Header Length",
    "Bwd Header Length": "Bwd Header Length",
    "Fwd Packets/s": "Fwd Packets/s",
    "Bwd Packets/s": "Bwd Packets/s",
    "Min Packet Length": "Packet Length Min",
    "Max Packet Length": "Packet Length Max",
    "Packet Length Mean": "Packet Length Mean",
    "Packet Length Std": "Packet Length Std",
    "Packet Length Variance": "Packet Length Variance",
    "FIN Flag Count": "FIN Flag Count",
    "SYN Flag Count": "SYN Flag Count",
    "RST Flag Count": "RST Flag Count",
    "PSH Flag Count": "PSH Flag Count",
    "ACK Flag Count": "ACK Flag Count",
    "URG Flag Count": "URG Flag Count",
    "CWE Flag Count": "CWE Flag Count",
    "ECE Flag Count": "ECE Flag Count",
    "Down/Up Ratio": "Down/Up Ratio",
    "Average Packet Size": "Avg Packet Size",
    "Avg Fwd Segment Size": "Avg Fwd Segment Size",
    "Avg Bwd Segment Size": "Avg Bwd Segment Size",
    "Fwd Header Length.1": "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk": "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk": "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate": "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk": "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk": "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate": "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets": "Subflow Fwd Packets",
    "Subflow Fwd Bytes": "Subflow Fwd Bytes",
    "Subflow Bwd Packets": "Subflow Bwd Packets",
    "Subflow Bwd Bytes": "Subflow Bwd Bytes",
    "Init_Win_bytes_forward": "Init Fwd Win Bytes",
    "Init_Win_bytes_backward": "Init Bwd Win Bytes",
    "act_data_pkt_fwd": "act_data_pkt_fwd",
    "min_seg_size_forward": "min_seg_size_forward",
    "Active Mean": "Active Mean",
    "Active Std": "Active Std",
    "Active Max": "Active Max",
    "Active Min": "Active Min",
    "Idle Mean": "Idle Mean",
    "Idle Std": "Idle Std",
    "Idle Max": "Idle Max",
    "Idle Min": "Idle Min",
    "Label": "Label",
    " Label": "Label",
}

# Attack label groupings — any non-BENIGN label → binary ATTACK
# Keep them as-is for multiclass
BENIGN_LABEL = "BENIGN"

# ---------------------------------------------------------------------------
# Feature engineering (must exactly match flowmeter.py's Flow.features())
# ---------------------------------------------------------------------------
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add log1p-transformed features that the existing model uses."""
    df = df.copy()
    dur_col = "Flow Duration"
    if dur_col in df.columns:
        df["FE_Log_Flow_Duration"] = np.log1p(df[dur_col].clip(lower=0))
    if "Total Fwd Packets" in df.columns:
        df["FE_Log_Total_Fwd_Packets"] = np.log1p(df["Total Fwd Packets"].clip(lower=0))
    if "Total Backward Packets" in df.columns:
        df["FE_Log_Total_Backward_Packets"] = np.log1p(df["Total Backward Packets"].clip(lower=0))
    return df


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
def load_cicids2017(data_dir: Path, sample: float = 1.0) -> pd.DataFrame:
    """Load all CIC-IDS2017 CSV/Parquet files from data_dir."""
    data_dir = Path(data_dir)
    csv_files = sorted(data_dir.rglob("*.csv"))
    parquet_files = sorted(data_dir.rglob("*.parquet"))

    files = parquet_files or csv_files
    if not files:
        raise FileNotFoundError(f"No CSV or Parquet files found in {data_dir}")

    log.info("Found %d file(s) in %s", len(files), data_dir)

    frames = []
    for path in files:
        log.info("  Loading: %s", path.name)
        try:
            if path.suffix == ".parquet":
                part = pd.read_parquet(path)
            else:
                part = pd.read_csv(path, low_memory=False)

            # Normalise column names
            part.columns = part.columns.astype(str).str.strip()
            part = part.rename(columns=COL_ALIASES)

            # Strip whitespace from Label
            if "Label" in part.columns:
                part["Label"] = part["Label"].astype(str).str.strip()

            frames.append(part)
            log.info("    → %d rows, %d cols", len(part), len(part.columns))
        except Exception as exc:
            log.warning("  Skipping %s: %s", path.name, exc)

    if not frames:
        raise RuntimeError("All files failed to load.")

    df = pd.concat(frames, ignore_index=True)
    log.info("Combined dataset: %d rows × %d cols", len(df), len(df.columns))

    if sample < 1.0:
        df = df.sample(frac=sample, random_state=42).reset_index(drop=True)
        log.info("Sampled %.0f%% → %d rows", sample * 100, len(df))

    return df


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------
def clean_dataset(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Clean and return (X_numeric, y_binary)."""
    # Drop non-feature columns
    drop_cols = [
        "Flow ID", "Source IP", "Destination IP", "Timestamp",
        "Source Port", "Destination Port",
        "_source_file",
    ]
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")

    if "Label" not in df.columns:
        raise ValueError("No 'Label' column found. Check column names.")

    y_raw = df["Label"].copy()
    X = df.drop(columns=["Label"])

    # Binary label: BENIGN=0, anything else=1
    y = (y_raw.str.casefold() != "benign").astype(int)

    log.info("Label distribution:\n%s", y_raw.value_counts().to_string())
    log.info("Binary: BENIGN=%d  ATTACK=%d", (y == 0).sum(), (y == 1).sum())

    # Convert all columns to numeric
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    # Replace ±inf → NaN
    X = X.replace([np.inf, -np.inf], np.nan)

    # Drop all-NaN or constant columns
    all_nan = X.columns[X.isna().all()].tolist()
    if all_nan:
        log.info("Dropping all-NaN columns: %s", all_nan)
        X = X.drop(columns=all_nan)

    constant = X.columns[X.nunique(dropna=True) <= 1].tolist()
    if constant:
        log.info("Dropping constant columns: %s", constant)
        X = X.drop(columns=constant)

    return X, y


# ---------------------------------------------------------------------------
# Feature selection
# ---------------------------------------------------------------------------
def select_features(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    n_features: int = 30,
    sample_n: int = 100_000,
) -> list[str]:
    """Use ExtraTreesClassifier to rank and select top features."""
    from sklearn.ensemble import ExtraTreesClassifier
    from sklearn.impute import SimpleImputer

    log.info("Selecting top %d features via ExtraTrees...", n_features)

    # Sub-sample for speed
    if len(X_train) > sample_n:
        idx = X_train.sample(n=sample_n, random_state=42).index
        X_s = X_train.loc[idx]
        y_s = y_train.loc[idx]
    else:
        X_s, y_s = X_train, y_train

    # Impute NaN for feature selection only
    imp = SimpleImputer(strategy="median")
    X_imp = imp.fit_transform(X_s)

    clf = ExtraTreesClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_imp, y_s)

    importances = pd.Series(clf.feature_importances_, index=X_train.columns)
    selected = importances.nlargest(n_features).index.tolist()

    log.info("Selected features:")
    for i, feat in enumerate(selected, 1):
        log.info("  %2d. %-40s %.4f", i, feat, importances[feat])

    return selected


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    n_features: int = 30,
) -> "tf.keras.Model":  # noqa: F821
    """Build and train the MLP neural network."""
    import tensorflow as tf

    tf.get_logger().setLevel("ERROR")

    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(n_features,)),
        tf.keras.layers.Dense(128, activation="relu"),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.30),
        tf.keras.layers.Dense(64, activation="relu"),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.20),
        tf.keras.layers.Dense(32, activation="relu"),
        tf.keras.layers.Dense(1, activation="sigmoid"),
    ])

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            tf.keras.metrics.Precision(name="precision"),
            tf.keras.metrics.Recall(name="recall"),
            tf.keras.metrics.AUC(name="roc_auc"),
        ],
    )

    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor="val_loss", patience=5, restore_best_weights=True
        ),
        tf.keras.callbacks.ReduceLROnPlateau(
            monitor="val_loss", factor=0.5, patience=2, min_lr=1e-6, verbose=0
        ),
    ]

    log.info("Training MLP (%d features, %d train samples)...", n_features, len(X_train))
    model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=40,
        batch_size=1024,
        callbacks=callbacks,
        class_weight={0: 1.0, 1: 2.0},  # penalise false negatives more
        verbose=1,
    )

    return model


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
def evaluate_model(
    model,
    X_test: np.ndarray,
    y_test: np.ndarray,
    threshold: float = 0.5,
    label: str = "Test",
) -> dict:
    """Print and return classification metrics."""
    from sklearn.metrics import (
        accuracy_score, classification_report, confusion_matrix,
        f1_score, precision_score, recall_score, roc_auc_score,
    )

    t0 = time.perf_counter()
    probs = model.predict(X_test, batch_size=4096, verbose=0).ravel()
    latency_ms = (time.perf_counter() - t0) * 1000 / len(X_test)

    preds = (probs >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, preds, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    metrics = {
        "dataset": label,
        "accuracy": accuracy_score(y_test, preds),
        "precision": precision_score(y_test, preds, zero_division=0),
        "recall": recall_score(y_test, preds, zero_division=0),
        "f1": f1_score(y_test, preds, zero_division=0),
        "roc_auc": roc_auc_score(y_test, probs),
        "false_positive_rate": fpr,
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
        "latency_ms_per_flow": latency_ms,
        "threshold": threshold,
    }

    print(f"\n{'='*60}")
    print(f"  {label} SET EVALUATION")
    print(f"{'='*60}")
    print(f"  Accuracy         : {metrics['accuracy']:.4f}")
    print(f"  Precision        : {metrics['precision']:.4f}")
    print(f"  Recall (TPR)     : {metrics['recall']:.4f}")
    print(f"  F1-score         : {metrics['f1']:.4f}")
    print(f"  ROC-AUC          : {metrics['roc_auc']:.4f}")
    print(f"  False-Positive   : {fpr:.4f}  ({fp} benign flagged as attack)")
    print(f"  Confusion matrix : TP={tp} TN={tn} FP={fp} FN={fn}")
    print(f"  Latency          : {latency_ms:.4f} ms / flow")
    print()
    print(classification_report(
        y_test, preds, target_names=["BENIGN", "ATTACK"], zero_division=0
    ))

    return metrics


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
def export_artifacts(
    model,
    imputer,
    scaler,
    selected_features: list[str],
    metrics: dict,
    out_dir: Path,
    threshold: float = 0.5,
) -> None:
    """Save model + preprocessing artifacts in the format expected by inference.py."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # Keras model
    model_path = out_dir / "ids_model.keras"
    model.save(str(model_path))
    log.info("Saved model → %s", model_path)

    # Preprocessing pickle (same keys as existing preprocessing.pkl)
    prep_path = out_dir / "preprocessing.pkl"
    joblib.dump(
        {
            "imputer": imputer,
            "scaler": scaler,
            "selected_features": list(selected_features),
        },
        prep_path,
    )
    log.info("Saved preprocessing → %s", prep_path)

    # Metadata JSON (compatible with existing metadata.json format)
    meta = {
        "project": "AI-Driven Network Intrusion Detection Firewall",
        "model_type": "TensorFlow/Keras binary classification MLP",
        "input_features": len(selected_features),
        "input_shape": [None, len(selected_features)],
        "output": {"0": "BENIGN", "1": "ATTACK"},
        "classification_threshold": threshold,
        "training_epochs_completed": 40,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "preprocessing_artifact": "preprocessing.pkl",
        "model_artifact": "ids_model.keras",
        "training_metrics": metrics,
        "dataset": "CIC-IDS2017",
        "selected_features": list(selected_features),
    }
    meta_path = out_dir / "metadata.json"
    meta_path.write_text(json.dumps(meta, indent=4))
    log.info("Saved metadata → %s", meta_path)

    log.info("✅ All artifacts saved to: %s", out_dir.resolve())


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Train CIC-IDS2017 IDS model")
    parser.add_argument("--data-dir", required=True, help="Directory with CIC-IDS2017 CSV/Parquet files")
    parser.add_argument("--out-dir", default="model_save_v2", help="Output directory for artifacts")
    parser.add_argument("--sample", type=float, default=1.0, help="Fraction of data to use (0-1)")
    parser.add_argument("--n-features", type=int, default=30, help="Number of features to select")
    parser.add_argument("--threshold", type=float, default=0.5, help="Classification threshold")
    parser.add_argument("--max-benign", type=int, default=300_000, help="Max benign samples (class balancing)")
    parser.add_argument("--no-smote", action="store_true", help="Skip SMOTE oversampling")
    args = parser.parse_args()

    log.info("=" * 60)
    log.info("  CIC-IDS2017 Training Pipeline")
    log.info("=" * 60)

    # Step 1: Load data
    df = load_cicids2017(Path(args.data_dir), sample=args.sample)

    # Step 2: Engineer features (add log1p columns to match flowmeter.py)
    df = engineer_features(df)

    # Step 3: Clean
    X, y = clean_dataset(df)

    # Step 4: Train/test split — split by index (temporal integrity if files are day-ordered)
    from sklearn.model_selection import train_test_split

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    X_train_raw, X_val_raw, y_train, y_val = train_test_split(
        X_train_raw, y_train, test_size=0.15, random_state=42, stratify=y_train
    )

    log.info(
        "Split: train=%d  val=%d  test=%d",
        len(X_train_raw), len(X_val_raw), len(X_test_raw),
    )

    # Step 5: Feature selection (on training set only)
    selected_features = select_features(X_train_raw, y_train, n_features=args.n_features)

    X_train_sel = X_train_raw[selected_features]
    X_val_sel   = X_val_raw[selected_features]
    X_test_sel  = X_test_raw[selected_features]

    # Step 6: Imputation + scaling (fitted on train only)
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler

    imputer = SimpleImputer(strategy="median")
    X_train_imp = imputer.fit_transform(X_train_sel)
    X_val_imp   = imputer.transform(X_val_sel)
    X_test_imp  = imputer.transform(X_test_sel)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_imp)
    X_val_scaled   = scaler.transform(X_val_imp)
    X_test_scaled  = scaler.transform(X_test_imp)

    # Step 7: Class balancing — cap benign + SMOTE
    y_train_arr = np.asarray(y_train, dtype=np.int32)
    benign_idx = np.where(y_train_arr == 0)[0]
    attack_idx = np.where(y_train_arr == 1)[0]

    if len(benign_idx) > args.max_benign:
        rng = np.random.default_rng(42)
        benign_idx = rng.choice(benign_idx, size=args.max_benign, replace=False)

    balanced_idx = np.concatenate([benign_idx, attack_idx])
    rng2 = np.random.default_rng(42)
    rng2.shuffle(balanced_idx)

    X_bal = X_train_scaled[balanced_idx]
    y_bal = y_train_arr[balanced_idx]

    log.info("After benign cap: BENIGN=%d  ATTACK=%d", (y_bal == 0).sum(), (y_bal == 1).sum())

    if not args.no_smote:
        try:
            from imblearn.over_sampling import SMOTE
            log.info("Applying SMOTE...")
            smote = SMOTE(random_state=42, k_neighbors=5)
            X_bal, y_bal = smote.fit_resample(X_bal, y_bal)
            log.info("After SMOTE: BENIGN=%d  ATTACK=%d", (y_bal == 0).sum(), (y_bal == 1).sum())
        except ImportError:
            log.warning("imbalanced-learn not installed; skipping SMOTE. Install with: pip install imbalanced-learn")

    # Step 8: Train
    model = train_model(
        X_bal, y_bal,
        X_val_scaled, np.asarray(y_val, dtype=np.int32),
        n_features=args.n_features,
    )

    # Step 9: Evaluate
    metrics = evaluate_model(model, X_test_scaled, np.asarray(y_test, dtype=np.int32), args.threshold)

    # Step 10: Export
    export_artifacts(
        model=model,
        imputer=imputer,
        scaler=scaler,
        selected_features=selected_features,
        metrics=metrics,
        out_dir=Path(args.out_dir),
        threshold=args.threshold,
    )

    # Step 11: Quick deployment instructions
    print("\n" + "=" * 60)
    print("  NEXT STEPS — Deploy to Raspberry Pi")
    print("=" * 60)
    print(f"  1. Verify the model locally:")
    print(f"     python training/validate_features.py --model-dir {args.out_dir}")
    print(f"")
    print(f"  2. Transfer to Pi:")
    print(f"     scp -r {args.out_dir}/ pi@raspberrypi.local:~/AI-driven-firewall-for-LAN-wLAN-analysis/model_save_v2/")
    print(f"")
    print(f"  3. Test on Pi (don't overwrite existing model yet):")
    print(f"     sudo venv/bin/python run.py --port 8080 --iface wlan0 --mode monitor")
    print(f"     # Edit config.yaml: model.dir: model_save_v2")
    print(f"")
    print(f"  4. If satisfied, swap:")
    print(f"     cp -r model_save/ model_save_backup/")
    print(f"     cp -r model_save_v2/ model_save/")
    print("=" * 60)


if __name__ == "__main__":
    main()

