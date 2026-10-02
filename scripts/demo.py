#!/usr/bin/env python3
"""
SecureMailScope — Offline Demo Script
Runs the full demonstration pipeline:
1. Generate demo PCAPs
2. Analyse each PCAP
3. Display results summary
4. Generate a PDF report
5. Print benchmark metrics
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.pcap.pipeline import analyse_pcap
from backend.reporting.generator import generate_html_report, generate_json_report, generate_pdf_report

DEMO_DIR = Path(__file__).parent.parent / "demo_pcaps"
REPORTS_DIR = Path(__file__).parent.parent / "reports"
SCRIPTS_DIR = Path(__file__).parent


def banner(text: str, width: int = 60) -> None:
    print("=" * width)
    print(f"  {text}")
    print("=" * width)


def section(text: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {text}")
    print('─' * 60)


def demo():
    banner("SecureMailScope Offline Demo")
    print("  SIH 2026 — PS 26159")
    print("  Passive Email Cryptographic Security Posture Analysis")
    print()

    # Check PCAPs
    pcaps = sorted(DEMO_DIR.glob("*.pcap"))
    if not pcaps:
        print("[!] No demo PCAPs found. Generating...")
        import subprocess
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "generate_pcaps.py")],
            cwd=str(SCRIPTS_DIR.parent),
        )
        if result.returncode != 0:
            print("[ERROR] PCAP generation failed. Ensure tshark is available.")
            sys.exit(1)
        pcaps = sorted(DEMO_DIR.glob("*.pcap"))

    print(f"  Found {len(pcaps)} demo PCAPs")
    for p in pcaps:
        print(f"    • {p.name}")
    print()

    REPORTS_DIR.mkdir(exist_ok=True)

    results = []
    section("Analysing PCAPs")

    for pcap in pcaps:
        print(f"\n  📂 {pcap.name}")
        t0 = time.perf_counter()
        try:
            result = analyse_pcap(str(pcap))
            elapsed = time.perf_counter() - t0

            score = result.risk_score.score
            level = result.risk_score.level
            crits = result.risk_score.critical_count
            highs = result.risk_score.high_count
            sessions = len(result.sessions)

            level_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "MINIMAL": "🟢"}.get(level, "⚪")

            print(f"     {level_icon} Risk Score: {score}/100 ({level})")
            print(f"     Sessions: {sessions}  Critical: {crits}  High: {highs}")

            if result.protocol_summary.tls_sessions:
                tls_vers = ", ".join(result.protocol_summary.tls_versions.keys())
                print(f"     TLS Versions: {tls_vers}")

            # Show top finding
            critical_findings = [f for f in result.all_findings if f.severity.value == "critical"]
            if critical_findings:
                f = critical_findings[0]
                print(f"     ⚠ {f.title}")

            # TLS 1.3 limitation note
            for s in result.sessions:
                if (s.tls_handshake and s.tls_handshake.tls_version.value == "TLS 1.3"
                        and s.tls_handshake.cert_observability.value == "not_observable"):
                    print(f"     ℹ TLS 1.3: Certificate not observable (correct passive behaviour)")
                    break

            # ML anomalies
            ml_anom = [s for s in result.sessions if s.is_anomalous]
            if ml_anom:
                print(f"     🤖 ML: {len(ml_anom)} session(s) flagged as anomalous")

            print(f"     ⏱ {elapsed:.3f}s")
            results.append(result)

        except Exception as exc:
            print(f"     [ERROR] {exc}")
            import traceback
            traceback.print_exc()

    # ── Summary ──────────────────────────────────────────────────────────────
    section("Demo Summary")

    total_sessions = sum(len(r.sessions) for r in results)
    total_critical = sum(r.risk_score.critical_count for r in results)
    total_high = sum(r.risk_score.high_count for r in results)
    total_ml = sum(r.risk_score.ml_anomaly_count for r in results)

    print(f"  PCAPs analysed:    {len(results)}")
    print(f"  Sessions found:    {total_sessions}")
    print(f"  Critical findings: {total_critical}")
    print(f"  High findings:     {total_high}")
    print(f"  ML anomalies:      {total_ml}")

    # ── Scenario highlights ──────────────────────────────────────────────────
    section("Scenario Highlights")

    for r in results:
        name = r.capture.pcap_filename
        score = r.risk_score.score
        level = r.risk_score.level
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "MINIMAL": "🟢"}.get(level, "⚪")
        cats = list(set(f.category.value for f in r.all_findings))
        anom = any(s.is_anomalous for s in r.sessions)
        print(f"  {icon} {name:<35} {score:>5}/100  {level:<8}  {'ML⚠' if anom else ''}")
        if cats:
            print(f"       Findings: {', '.join(cats)}")

    # ── PDF Report ────────────────────────────────────────────────────────────
    if results:
        section("Generating PDF Report")
        # Use the most interesting result (lowest score)
        worst = min(results, key=lambda r: r.risk_score.score)
        pdf_path = REPORTS_DIR / f"demo_{worst.capture.pcap_filename.replace('.pcap', '')}.pdf"
        try:
            generate_pdf_report(worst, str(pdf_path))
            print(f"  ✓ PDF report: {pdf_path}")
        except Exception as exc:
            print(f"  [warn] PDF generation failed: {exc}")

        # JSON report
        json_path = REPORTS_DIR / "demo_results.json"
        summary = {
            "demo_run": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pcaps": [
                {
                    "filename": r.capture.pcap_filename,
                    "score": r.risk_score.score,
                    "level": r.risk_score.level,
                    "sessions": len(r.sessions),
                    "critical": r.risk_score.critical_count,
                    "high": r.risk_score.high_count,
                }
                for r in results
            ],
        }
        with open(json_path, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"  ✓ JSON summary: {json_path}")

    print()
    banner("Demo Complete")
    print("  To start the dashboard:")
    print("    Backend:  just backend")
    print("    Frontend: just frontend")
    print("    Then open: http://localhost:5173")
    print()


if __name__ == "__main__":
    demo()
