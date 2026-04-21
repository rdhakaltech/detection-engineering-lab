# Detection Engineering Lab

A public portfolio repository focused on practical detection engineering concepts, sample detections, triage workflows, and reusable security analytics content.

## Purpose
This repository demonstrates how to design, document, and validate security detections using simulated data and vendor-neutral logic. It is intended for portfolio and learning purposes only.

## Focus Areas
- Windows process creation detections
- PowerShell abuse detection
- Suspicious command-line behavior
- Authentication anomaly detection
- Proxy and user behavior analytics
- Triage and false-positive reduction

## Repository Structure
- `detections/` - documented detection use cases
- `sample_logs/` - fake lab logs for testing
- `triage_guides/` - investigation steps and analyst workflow
- `scripts/` - helper scripts for log generation and parsing
- `mappings/` - MITRE ATT&CK mappings

## Principles
- No company-specific content
- No proprietary dashboards or internal detections
- All sample data is simulated or sanitized
- Focus on reusable, portable detection ideas

## Featured Detection Ideas
1. Encoded PowerShell execution via Event ID 4688
2. Suspicious command-line abuse patterns
3. Authentication anomaly detection
4. Proxy-based user/device anomaly tracking

## Author
Ram Dhakal
Senior Security Engineer | Detection Engineering | Security Automation
