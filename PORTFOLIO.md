# RATShield XDR Pro

![Project banner](assets/project-banner.svg)

## Portfolio Summary

RATShield XDR Pro is a defensive endpoint triage platform I built to help analysts identify RAT-like behavior across Windows, Linux, and Android ADB-connected devices.

The project combines a modern XDR-style dashboard with an evidence-rich detection engine, so each finding is easy to review, explain, and export.

## Problem

Security teams often need to investigate suspicious activity quickly, but raw telemetry can be noisy and fragmented.

RATShield XDR Pro addresses that by bringing together:

- process and persistence inspection
- command-line and script analysis
- lightweight static checks
- Android permission cluster review
- timeline and MITRE correlation
- HTML and JSON reporting

## Solution

I designed the project around a simple analyst workflow:

1. Run a safe demo or live scan
2. Review the highest-risk indicators first
3. Click any finding to inspect evidence, MITRE mapping, and remediation steps
4. Export a shareable report for documentation or handoff

![Dashboard preview](assets/dashboard-preview.svg)

## What I Built

- A responsive single-page investigation dashboard
- A risk scoring engine with severity, confidence, and verdict output
- A local host scanner with process, network, file, and persistence checks
- A safe demo mode for presentations
- Android ADB scanning support
- Reusable SVG visuals for the app, README, and landing page
- A GitHub Pages-ready `index.html` landing page

## Detection Features

- PowerShell loader and obfuscation signals
- `schtasks` masquerading and persistence clues
- LOLBin delivery patterns such as `mshta`, `rundll32`, `regsvr32`, and `certutil`
- Screen capture and email exfiltration markers
- Hidden-window and execution-policy tampering
- Android dangerous-permission clustering

## Visuals

| Project banner | Dashboard preview |
| --- | --- |
| ![Banner](assets/project-banner.svg) | ![Dashboard](assets/dashboard-preview.svg) |

## Impact

This project demonstrates:

- defensive product thinking
- security UX polish
- malware triage logic
- evidence-driven reporting
- a presentation-friendly public page

## Tech Stack

- Python
- FastAPI
- Pydantic
- HTML, CSS, JavaScript
- psutil
- Android ADB

## Links

- [Repository README](README.md)
- [GitHub Pages landing page](index.html)
- [Profile README template](profile/README.md)

## Safety

This project is strictly for defensive security research, SOC labs, malware analysis training, and authorized endpoint assessment.
