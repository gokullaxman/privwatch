# PrivWatch 3.0 — Installation Guide

## 1. System Requirements

- **Operating System:**
  - Full Support: Ubuntu (20.04+), Debian (11+), Kali Linux, Fedora (38+), RHEL/CentOS (8+), Arch Linux.
  - Partial/Degraded Mode: Other POSIX systems, Windows (for offline report generation, dashboard review, and test execution).
- **Python:** Python 3.8 to Python 3.13+
- **Privileges:**
  - Standard user: Sufficient for basic user-level audits, timeline reconstruction, and dashboard operations.
  - Root (UID 0): Recommended for full filesystem SUID scanning, `/etc/shadow` audits, reading restricted auditd logs, and live monitoring.

---

## 2. Dependencies & Installation

PrivWatch 3.0 uses Python standard library for core functions and optional modern libraries for the Web Dashboard and PDF generation:

```bash
# Clone the repository
git clone https://github.com/charith-Penugonda/privwatch.git
cd privwatch

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install core and web dashboard dependencies
pip install -r requirements.txt
```

### Core Dependencies (`requirements.txt`):
```text
fastapi>=0.100.0
uvicorn>=0.20.0
pydantic>=2.0.0
reportlab>=3.6.0
psutil>=5.9.0
pytest>=7.0.0
```

---

## 3. Verifying Installation

Verify that all Python modules compile cleanly and that the automated test suite passes:

```bash
# 1. Bytecode compilation check
python3 -m compileall .

# 2. Automated test suite execution
python3 -m pytest -v
```

All 34 automated unit, integration, and security tests should pass with 100% success.

