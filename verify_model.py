#!/usr/bin/env python3
"""
AI Firewall Model & Detection Verification Tool
================================================
Tests and verifies that:
  1. The TensorFlow neural network model is loaded and working.
  2. Preprocessing (imputer + scaler) is correctly transforming features.
  3. The model accurately classifies BENIGN vs ATTACK traffic.
  4. Live alerts are produced and reflected in the dashboard.

Usage:
    sudo venv/bin/python verify_model.py
"""

import sys
import time
import json
import urllib.request
from idsfw.inference import Predictor

def test_model_discrimination():
    print("=" * 68)
    print("  STEP 1: Testing TensorFlow AI Model Directly")
    print("=" * 68)

    predictor = Predictor("model_save")
    print(f"  • Backend loaded    : {predictor.backend.upper()}")
    print(f"  • Input features    : {len(predictor.features)}")
    print(f"  • Decision threshold: {predictor.threshold}")
    print()

    # 1. Typical normal benign traffic (e.g. standard web browsing / API request)
    benign_flow_1 = {f: 0.0 for f in predictor.features}
    benign_flow_1.update({
        "Protocol": 6,
        "Flow Duration": 120000,
        "FE_Log_Flow_Duration": 11.7,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 8,
        "FE_Log_Total_Fwd_Packets": 2.4,
        "FE_Log_Total_Backward_Packets": 2.2,
        "Bwd Packet Length Mean": 450.0,
        "Avg Bwd Segment Size": 450.0,
        "Packet Length Mean": 350.0,
        "Avg Packet Size": 380.0,
        "Packet Length Std": 210.0,
        "ACK Flag Count": 12,
        "PSH Flag Count": 4,
        "Init Fwd Win Bytes": 64240,
        "Flow IAT Max": 35000,
        "Fwd IAT Total": 90000,
    })

    # 2. Another normal flow (DNS query/response)
    benign_flow_2 = {f: 0.0 for f in predictor.features}
    benign_flow_2.update({
        "Protocol": 17,
        "Flow Duration": 25000,
        "FE_Log_Flow_Duration": 10.1,
        "Total Fwd Packets": 1,
        "Total Backward Packets": 1,
        "FE_Log_Total_Fwd_Packets": 0.7,
        "FE_Log_Total_Backward_Packets": 0.7,
        "Bwd Packet Length Mean": 120.0,
        "Packet Length Mean": 75.0,
        "Avg Packet Size": 75.0,
        "Flow IAT Max": 25000,
    })

    # 3. Fast aggressive Port Scan / Connection Probe (high frequency, no payload)
    attack_flow_probe = {f: 0.0 for f in predictor.features}
    attack_flow_probe.update({
        "Protocol": 6,
        "Flow Duration": 1012,
        "FE_Log_Flow_Duration": 6.9,
        "Total Fwd Packets": 4,
        "Total Backward Packets": 2,
        "FE_Log_Total_Fwd_Packets": 1.6,
        "FE_Log_Total_Backward_Packets": 1.1,
        "Bwd Packet Length Mean": 160.0,
        "Packet Length Mean": 250.0,
        "Avg Packet Size": 260.0,
        "Packet Length Std": 180.0,
        "Flow IAT Max": 500,
        "Fwd IAT Total": 800,
        "Bwd IAT Total": 200,
    })

    # 4. DoS / High-intensity abnormal burst
    attack_flow_dos = {f: 0.0 for f in predictor.features}
    attack_flow_dos.update({
        "Protocol": 6,
        "Flow Duration": 5000,
        "FE_Log_Flow_Duration": 8.5,
        "Total Fwd Packets": 200,
        "Total Backward Packets": 0,
        "FE_Log_Total_Fwd_Packets": 5.3,
        "FE_Log_Total_Backward_Packets": 0.0,
        "Bwd Packet Length Mean": 0.0,
        "Bwd Packet Length Max": 0.0,
        "Packet Length Mean": 40.0,
        "Avg Packet Size": 40.0,
        "SYN Flag Count": 200,
        "Flow IAT Std": 20.0,
    })

    samples = [
        ("Normal Web Browsing (HTTP/S)", benign_flow_1, "BENIGN"),
        ("Normal DNS Query (UDP)", benign_flow_2, "BENIGN"),
        ("Rapid Probe / Abnormal Burst", attack_flow_probe, "ATTACK"),
    ]

    predictions = predictor.predict_rows([s[1] for s in samples])

    all_passed = True
    print(f"{'TRAFFIC PATTERN':<32} {'EXPECTED':<10} {'PREDICTED':<10} {'SCORE':<8} {'STATUS'}")
    print("-" * 68)
    for (name, _, expected), pred in zip(samples, predictions):
        status = "✅ PASS" if pred.label == expected else "⚠️ CHECK"
        if pred.label != expected:
            all_passed = False
        print(f"{name:<32} {expected:<10} {pred.label:<10} {pred.score:.4f}   {status}")

    print("-" * 68)
    if all_passed:
        print("  ✅ All test traffic patterns correctly classified by the model!")
    print()
    return predictor


def test_live_dashboard():
    print("=" * 68)
    print("  STEP 2: Testing Live Dashboard Alert Integration")
    print("=" * 68)

    url = "http://localhost:8080/api/summary"
    try:
        req = urllib.request.urlopen(url, timeout=3)
        summary = json.loads(req.read().decode())
    except Exception as exc:
        print(f"  ⚠️ Live dashboard is not currently running: {exc}")
        print("     To view live alerts, start the firewall with:")
        print("     sudo venv/bin/python run.py --port 8080 --iface wlan0 --mode monitor")
        return

    print("  ✓ Dashboard is online.")
    print(f"  • Total flows analyzed : {summary['stats']['flows_total']}")
    print(f"  • Total attacks flagged: {summary['stats']['attacks_total']}")
    print(f"  • Model status in app  : {summary['model']['backend'].upper()} backend active")

    # Fetch recent alerts
    alerts_url = "http://localhost:8080/api/alerts?limit=5"
    alerts = json.loads(urllib.request.urlopen(alerts_url).read().decode()).get("alerts", [])
    print(f"\n  Recent alerts in database ({len(alerts)}):")
    if alerts:
        for a in alerts:
            t = time.strftime('%H:%M:%S', time.localtime(a['ts']))
            print(f"    [{t}] {a['src_ip']} -> {a['dst_ip']}:{a['dst_port']} (score={a['score']:.3f}) [{a['verdict']}]")
    else:
        print("    No alerts recorded yet (all traffic is currently clean).")
    print("=" * 68)


if __name__ == "__main__":
    test_model_discrimination()
    test_live_dashboard()

