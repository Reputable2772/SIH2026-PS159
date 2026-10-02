# SecureMailScope — Justfile
# Usage: just <command>

set dotenv-load := false

BACKEND_DIR := "backend"
FRONTEND_DIR := "frontend"
SCRIPTS_DIR := "scripts"
PYTHON := "python"

# Show available commands
default:
    @just --list

# ─── Development ────────────────────────────────────────────────────────────

# Start backend API server
backend:
    cd {{BACKEND_DIR}} && \
    PYTHONPATH="$(dirname $(pwd))" \
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# Start frontend dev server
frontend:
    cd {{FRONTEND_DIR}} && npm run dev

# Start both backend and frontend (requires tmux or two terminals)
dev:
    @echo "Start backend:  just backend"
    @echo "Start frontend: just frontend"
    @echo "Or run both:    just backend & just frontend"

# ─── Data Generation ────────────────────────────────────────────────────────

# Generate synthetic test PCAPs (requires tshark + openssl in PATH)
gen-pcaps:
    @echo "Generating synthetic test PCAPs..."
    @echo "Note: requires tshark and openssl (available in nix devshell)"
    {{PYTHON}} {{SCRIPTS_DIR}}/generate_pcaps.py

# ─── Testing & Benchmarking ─────────────────────────────────────────────────

# Run unit + integration tests
test:
    PYTHONPATH="." pytest tests/ -v --tb=short

# Run benchmark evaluation suite
benchmark:
    @echo "Running SecureMailScope evaluation benchmark..."
    PYTHONPATH="." {{PYTHON}} benchmark/evaluate.py

# Run benchmark and save results
benchmark-save:
    PYTHONPATH="." {{PYTHON}} benchmark/evaluate.py 2>&1 | tee evidence/benchmarks/benchmark_$(date +%Y%m%d_%H%M%S).txt

# ─── Demo ───────────────────────────────────────────────────────────────────

# Run full offline demo
demo:
    @echo ""
    @echo "╔══════════════════════════════════════════════════════╗"
    @echo "║          SecureMailScope Offline Demo                ║"
    @echo "║  SIH 2026 — PS 26159                                 ║"
    @echo "╚══════════════════════════════════════════════════════╝"
    @echo ""
    {{PYTHON}} {{SCRIPTS_DIR}}/demo.py

# ─── Reports ────────────────────────────────────────────────────────────────

# Analyse a PCAP and generate all reports
analyse pcap:
    PYTHONPATH="." {{PYTHON}} -c "import json, pathlib; from backend.pcap.pipeline import analyse_pcap; from backend.reporting.generator import generate_json_report, generate_html_report, generate_pdf_report; r = analyse_pcap('{{pcap}}'); pathlib.Path('reports').mkdir(exist_ok=True); open('reports/report.json','w').write(json.dumps(generate_json_report(r), indent=2)); open('reports/report.html','w').write(generate_html_report(r)); generate_pdf_report(r, 'reports/report.pdf'); print('Reports saved to reports/'); print(f'Score: {r.risk_score.score}/100 ({r.risk_score.level})'); print(f'Findings: {len(r.all_findings)}')"

# ─── ML Model ───────────────────────────────────────────────────────────────

# Pre-train and save the anomaly detection model
train-model:
    PYTHONPATH="." {{PYTHON}} -c "from backend.anomaly.detector import TLSAnomalyDetector; det = TLSAnomalyDetector(); det.train(); det.save(); print('Anomaly model trained and saved.')"

# ─── Frontend Build ──────────────────────────────────────────────────────────

# Install frontend dependencies
frontend-install:
    cd {{FRONTEND_DIR}} && npm install

# Build production frontend
frontend-build:
    cd {{FRONTEND_DIR}} && npm run build

# ─── Utilities ──────────────────────────────────────────────────────────────

# Verify environment is properly set up
check:
    @echo "Checking SecureMailScope environment..."
    @which tshark && echo "  ✓ tshark found" || echo "  ✗ tshark NOT found"
    @which openssl && echo "  ✓ openssl found" || echo "  ✗ openssl NOT found"
    @which tcpdump && echo "  ✓ tcpdump found" || echo "  ✗ tcpdump NOT found (optional)"
    @{{PYTHON}} -c "import fastapi; print('  ✓ fastapi', fastapi.__version__)"
    @{{PYTHON}} -c "import sklearn; print('  ✓ scikit-learn', sklearn.__version__)"
    @{{PYTHON}} -c "import cryptography; print('  ✓ cryptography', cryptography.__version__)"
    @{{PYTHON}} -c "import dpkt; print('  ✓ dpkt available')"
    @echo ""
    @echo "Environment OK. Run 'just gen-pcaps' to generate test data."

# Clean generated files
clean:
    rm -rf demo_pcaps/_certs
    rm -rf backend/anomaly/isolation_forest.pkl backend/anomaly/scaler.pkl
    rm -rf reports/
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find . -name "*.pyc" -delete 2>/dev/null || true

# Full clean including PCAPs
clean-all: clean
    rm -rf demo_pcaps/*.pcap
