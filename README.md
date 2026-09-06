# CL8 — Multi-Cloud CSPM Posture Auditor

Multi-cloud security posture management across AWS, GCP, and Azure with compliance scoring.

## Overview

This project implements a multi-cloud CSPM posture auditor that:
- Parses a unified asset JSON spanning AWS, GCP, and Azure resources
- Applies a policy rule base covering public exposure, encryption, IAM, logging, and bucket versioning
- Computes compliance scores per cloud/framework with letter grades
- Emits text + optional CSV reports
- Offline demo with embedded sample assets across all three providers

## Features

- **Multi-Cloud Support**: Unified asset format for AWS, GCP, and Azure resources
- **Policy Rule Base**: 11 rules covering storage, compute, IAM, SQL, and networking
- **Compliance Scoring**: Per-framework score with A–F letter grades
- **Violation Report**: Severity-classified findings (CRITICAL/HIGH/MEDIUM)
- **CSV Export**: Machine-readable output for dashboards and pipelines
- **Offline Demo**: Embedded sample data runs without credentials

## Dependencies

**None** — uses only Python standard library (`json`, `csv`, `argparse`, `collections`).

## Installation

```bash
# No external dependencies required
python3 cspm.py
```

## Usage

```bash
# Run offline demo with embedded sample data (no assets, exit 0)
python3 firmware/cspm.py

# Audit the bundled asset inventory fixture (offline)
python3 firmware/cspm.py --assets fixtures/assets.json

# Export violations (CSV + JSON) to a specific base path
python3 firmware/cspm.py --assets fixtures/assets.json --output reports/cl8-cspm

# CI-friendly: exit 2 when CRITICAL violations exist
python3 firmware/cspm.py --assets fixtures/assets.json --exit-code-on-findings; echo $?
```

## Exit Codes

- `0` — completed cleanly (or demo finished without explicit CRITICAL gate)
- `1` — error (unreadable/missing asset inventory)
- `2` — CRITICAL violations present with `--exit-code-on-findings`

## Live Lab Test Plan

Runs entirely offline on the bundled fixture `fixtures/assets.json` — no cloud account, no credentials, no network.

1. **Demo**: `python3 firmware/cspm.py` — no-arg mode uses embedded demo data and exits `0`.
2. **Fixture run**: `python3 firmware/cspm.py --assets fixtures/assets.json` — produce CRITICAL findings (PUB-001 public storage, SQL-001 firewall allow-all), HIGH (ENC-001, IAM-001/002, SQL-002), MEDIUM (LOG-001, VER-001, IAM-003, NET-001).
3. **Reports**: verify `reports/cl8-cspm.csv` and `reports/cl8-cspm.json` — counts match, JSON has `violation_count`, `critical_count`, `summary`.
4. **CI exit code**: `--exit-code-on-findings` returns `2`.
5. **Unit tests**: `python3 -m unittest discover -s tests -v` — all pass (covers rule engine, fixture, embedded demo, compliant-asset case).

## Metrics

- Real detection paths exercised offline: all 11 `POLICY_RULES` against multi-cloud assets (AWS/GCP/Azure)
- 8 unit tests cover the rule engine on the fixture and embedded demo
- Compliance scoring with A–F grades per framework plus overall score
- Every violation carries `rule_id`, `rule_name`, `severity`, `provider`, `type`, `asset`
- Exit-code contract: `0` clean / `1` error / `2` CRITICAL findings (with `--exit-code-on-findings`)
- Zero third-party dependencies; offline modes require no cloud access

## IMPORTANT: Read before use.

```
  Assets loaded: 10
  Providers: aws, azure, gcp
  Policy rules: 11

============================================================
  MULTI-CLOUD CSPM POSTURE AUDIT
============================================================

  [AWS] s3/my-public-bucket:
    [!!] CRITICAL PUB-001 — No Public Access on Storage
    [!!] HIGH     ENC-001 — Encryption Disabled

  [AZURE] sql/prod-sql-db:
    [!!] CRITICAL SQL-001 — SQL Firewall Allows All
    [!!] HIGH     SQL-002 — SQL Auditing Disabled

============================================================
  COMPLIANCE SCORES BY FRAMEWORK
============================================================
  AWS-S3               [================----]  81.8% (B)
  GCP-IAM              [==================--]  90.9% (A)
  AZURE-VM             [==============------]  72.7% (C)

  OVERALL                                      79.1% (87/110 passed)
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the cloud account owner before using this tool
- Unauthorized scanning of cloud environments is illegal under federal and state laws
- This tool should ONLY be used on cloud accounts you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **AWS/GCP/Azure Acceptable Use Policies**: Unauthorized probing violates cloud provider ToS
- **State Laws**: Many states have additional computer crime statutes
- **GDPR/CCPA**: Cloud data access may be subject to privacy regulations

### Acceptable Use
- Auditing security posture of your own cloud environments
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Scanning cloud accounts you do not own
- Exploiting discovered misconfigurations without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
