# RATShield XDR Pro v0.3

RATShield XDR Pro is an early-stage defensive research prototype for identifying RAT-like behavior on Windows, Linux, and Android devices.

## Features

- FastAPI backend
- XDR-style frontend dashboard
- Process and persistence inspection
- Android ADB analysis support
- Risk scoring engine
- HTML and JSON reporting
- API-key protection support
- Allowlisting support
- MITRE ATT&CK mapping
- CI-ready project structure

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.app.main:app --reload
```

## Security Notice

This project is for defensive security research, SOC labs, malware analysis training, and authorized testing only.
