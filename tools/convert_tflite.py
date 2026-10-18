#!/usr/bin/env python3
"""Convert the trained Keras model to TFLite (optional, for lower memory use).

Run this on a machine that has TensorFlow installed (the Pi works fine):

    venv/bin/python tools/convert_tflite.py \
        --model model_save/ids_model.keras \
        --out model_save/ids_model.tflite [--quantize]

The runtime picks up a TFLite file automatically when TensorFlow is not
installed (see idsfw/inference.py).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="model_save/ids_model.keras")
    parser.add_argument("--out", default="model_save/ids_model.tflite")
    parser.add_argument("--quantize", action="store_true", help="float16 quantization")
    args = parser.parse_args()

    try:
        import tensorflow as tf
    except ImportError:
        print("TensorFlow is required to convert the model", file=sys.stderr)
        return 2

    model_path = Path(args.model)
    if not model_path.exists():
        print(f"model not found: {model_path}", file=sys.stderr)
        return 2

    model = tf.keras.models.load_model(model_path, compile=False)
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    if args.quantize:
        converter.optimizations = [tf.lite.Optimize.DEFAULT]
        converter.target_spec.supported_types = [tf.float16]
    tflite_model = converter.convert()

    out_path = Path(args.out)
    out_path.write_bytes(tflite_model)
    print(f"wrote {out_path} ({out_path.stat().st_size / 1024:.1f} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
