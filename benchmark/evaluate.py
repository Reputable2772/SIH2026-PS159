#!/usr/bin/env python3
"""
SecureMailScope — Benchmark / Evaluation Suite
Measures detection accuracy against known-expectation test PCAPs.

Output format suitable for screenshots and SIH PPT evidence.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.pcap.pipeline import analyse_pcap

DEMO_DIR = Path(__file__).parent.parent / "demo_pcaps"
EXPECTED_FILE = Path(__file__).parent / "expected_results.json"

# ---------------------------------------------------------------------------
# Expected results for each scenario
# ---------------------------------------------------------------------------

EXPECTED_RESULTS = {
    "01_secure_tls12.pcap": {
        "protocol": "SMTP",
        "has_tls": True,
        "expected_findings": [],
        "expected_finding_categories": [],
        "cert_observable": True,
        "anomalous": False,
        "description": "Secure TLS 1.2 SMTP — no findings expected",
    },
    "02_legacy_tls10.pcap": {
        "protocol": "SMTP",
        "has_tls": True,
        "expected_finding_categories": ["deprecated_tls"],
        "cert_observable": True,
        "anomalous": True,
        "description": "Legacy TLS 1.0 — deprecated_tls finding expected",
    },
    "03_weak_cipher.pcap": {
        "protocol": "SMTP",
        "has_tls": True,
        "expected_finding_categories": ["weak_cipher", "no_forward_secrecy"],
        "cert_observable": True,
        "anomalous": True,
        "description": "Weak cipher (RSA key exchange) — weak_cipher and no_fs expected",
    },
    "04_expired_cert.pcap": {
        "protocol": "IMAP",
        "has_tls": True,
        "expected_finding_categories": ["expired_certificate"],
        "cert_observable": True,
        "anomalous": True,
        "description": "Expired certificate — expired_certificate finding expected",
    },
    "05_starttls_fallback.pcap": {
        "protocol": "SMTP",
        "has_tls": False,
        "expected_finding_categories": ["starttls_anomaly"],
        "cert_observable": False,
        "anomalous": True,
        "description": "STARTTLS fallback — starttls_anomaly finding expected",
    },
    "06_anomalous_handshake.pcap": {
        "protocol": "SMTP",
        "has_tls": True,
        "expected_finding_categories": ["weak_key", "no_forward_secrecy"],
        "cert_observable": True,
        "anomalous": True,
        "description": "Anomalous: weak key, no FS — ml_anomaly or rule finding expected",
    },
    "07_plaintext_smtp.pcap": {
        "protocol": "SMTP",
        "has_tls": False,
        "expected_finding_categories": ["starttls_anomaly"],
        "cert_observable": False,
        "anomalous": False,
        "description": "Plaintext SMTP — no_tls finding expected",
    },
}


# ---------------------------------------------------------------------------
# Evaluation Metrics
# ---------------------------------------------------------------------------

class Metrics:
    def __init__(self):
        self.tp = 0
        self.fp = 0
        self.fn = 0
        self.tn = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def evaluate_all() -> dict:
    """Run evaluation against all available demo PCAPs."""
    if not DEMO_DIR.exists() or not list(DEMO_DIR.glob("*.pcap")):
        print("[ERROR] No demo PCAPs found.")
        print(f"        Run: python scripts/generate_pcaps.py")
        sys.exit(1)

    pcaps = sorted(DEMO_DIR.glob("*.pcap"))
    print("=" * 60)
    print("SecureMailScope Benchmark / Evaluation")
    print("=" * 60)
    print(f"PCAPs found: {len(pcaps)}")
    print()

    rule_metrics = Metrics()
    ml_metrics = Metrics()
    results = []
    total_sessions = 0
    total_critical = total_high = 0
    total_time = 0.0
    pcaps_processed = 0

    for pcap in pcaps:
        fname = pcap.name
        expected = EXPECTED_RESULTS.get(fname)
        if not expected:
            print(f"  [skip] {fname} — no expected result defined")
            continue

        print(f"  Analysing: {fname}")
        print(f"    {expected['description']}")

        t0 = time.perf_counter()
        try:
            result = analyse_pcap(str(pcap))
        except Exception as exc:
            print(f"    [ERROR] {exc}")
            continue
        elapsed = time.perf_counter() - t0
        total_time += elapsed
        pcaps_processed += 1

        sessions_n = len(result.sessions)
        total_sessions += sessions_n
        total_critical += result.risk_score.critical_count
        total_high += result.risk_score.high_count

        # Collect actual finding categories
        actual_cats = set(f.category.value for f in result.all_findings if not f.is_ml_finding)
        expected_cats = set(expected.get("expected_finding_categories", []))

        # Rule engine metrics
        should_have_finding = bool(expected_cats)
        has_finding = bool(actual_cats)

        if should_have_finding and has_finding:
            rule_metrics.tp += 1
            hit_cats = actual_cats & expected_cats
            miss_cats = expected_cats - actual_cats
            print(f"    ✓ Rule findings: {actual_cats}")
            if miss_cats:
                print(f"    ⚠ Missing expected: {miss_cats}")
        elif should_have_finding and not has_finding:
            rule_metrics.fn += 1
            print(f"    ✗ Missed expected findings: {expected_cats}")
        elif not should_have_finding and has_finding:
            rule_metrics.fp += 1
            print(f"    ✗ False positive findings: {actual_cats}")
        else:
            rule_metrics.tn += 1
            print(f"    ✓ Correctly clean (no findings)")

        # ML anomaly metrics
        expected_anom = expected.get("anomalous", False)
        actual_anom = any(s.is_anomalous for s in result.sessions)
        if expected_anom and actual_anom:
            ml_metrics.tp += 1
        elif expected_anom and not actual_anom:
            ml_metrics.fn += 1
        elif not expected_anom and actual_anom:
            ml_metrics.fp += 1
        else:
            ml_metrics.tn += 1

        # TLS 1.3 cert observability check
        tls13_sessions = [s for s in result.sessions
                          if s.tls_handshake and
                          s.tls_handshake.tls_version.value == "TLS 1.3"]
        for s in tls13_sessions:
            if s.tls_handshake and s.tls_handshake.cert_observability.value == "not_observable":
                print(f"    ✓ TLS 1.3 cert limitation correctly reported")

        results.append({
            "pcap": fname,
            "sessions": sessions_n,
            "risk_score": result.risk_score.score,
            "risk_level": result.risk_score.level,
            "rule_tp": rule_metrics.tp,
            "actual_findings": list(actual_cats),
            "expected_findings": list(expected_cats),
            "anomalous": actual_anom,
            "processing_time": round(elapsed, 3),
        })
        print(f"    Score: {result.risk_score.score}/100 ({result.risk_score.level})  "
              f"Sessions: {sessions_n}  Time: {elapsed:.3f}s")
        print()

    # ---------------------------------------------------------------------------
    # Summary Report
    # ---------------------------------------------------------------------------
    print("=" * 60)
    print("Evaluation Summary")
    print("=" * 60)
    print(f"PCAPs processed        {pcaps_processed}")
    print(f"Sessions analyzed      {total_sessions}")
    print(f"Critical findings      {total_critical}")
    print(f"High findings          {total_high}")
    print()
    print("Rule Engine Detection")
    print(f"  True Positives       {rule_metrics.tp}")
    print(f"  False Positives      {rule_metrics.fp}")
    print(f"  False Negatives      {rule_metrics.fn}")
    print(f"  True Negatives       {rule_metrics.tn}")
    print(f"  Precision            {rule_metrics.precision:.3f}")
    print(f"  Recall               {rule_metrics.recall:.3f}")
    print(f"  F1 Score             {rule_metrics.f1:.3f}")
    print()
    print("ML Anomaly Detection")
    print(f"  True Positives       {ml_metrics.tp}")
    print(f"  False Positives      {ml_metrics.fp}")
    print(f"  False Negatives      {ml_metrics.fn}")
    print(f"  True Negatives       {ml_metrics.tn}")
    print(f"  Precision            {ml_metrics.precision:.3f}")
    print(f"  Recall               {ml_metrics.recall:.3f}")
    print(f"  F1 Score             {ml_metrics.f1:.3f}")
    print()
    if pcaps_processed > 0:
        print(f"Mean analysis time     {total_time/pcaps_processed:.3f}s")
    print(f"Total analysis time    {total_time:.3f}s")
    print("=" * 60)
    print()
    print("NOTE: All metrics are computed automatically from the benchmark.")
    print("      Results reflect actual analysis of the demo_pcaps/ corpus.")
    print("      Metrics may vary with PCAP content captured on your system.")
    print("=" * 60)

    return {
        "pcaps_processed": pcaps_processed,
        "total_sessions": total_sessions,
        "rule_metrics": {
            "precision": rule_metrics.precision,
            "recall": rule_metrics.recall,
            "f1": rule_metrics.f1,
            "tp": rule_metrics.tp,
            "fp": rule_metrics.fp,
            "fn": rule_metrics.fn,
            "tn": rule_metrics.tn,
        },
        "ml_metrics": {
            "precision": ml_metrics.precision,
            "recall": ml_metrics.recall,
            "f1": ml_metrics.f1,
            "tp": ml_metrics.tp,
            "fp": ml_metrics.fp,
            "fn": ml_metrics.fn,
            "tn": ml_metrics.tn,
        },
        "mean_time_s": total_time / pcaps_processed if pcaps_processed else 0,
        "total_time_s": total_time,
        "per_pcap": results,
    }


if __name__ == "__main__":
    results = evaluate_all()
    out = Path(__file__).parent / "benchmark_results.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results saved to: {out}")
