# RATShield XDR Pro v0.3

RATShield XDR Pro is a defensive endpoint triage and detection platform for identifying RAT-like behavior on Windows, Linux, and Android devices.

The project focuses on practical host inspection, suspicious behavior scoring, evidence collection, reporting, and SOC-ready investigation workflows.

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

Use this project only for defensive security research, SOC labs, malware analysis training, and authorized endpoint assessment.
