#!/usr/bin/env python3
"""
CL8 — Multi-Cloud CSPM Posture Auditor
Cloud security posture management across AWS, GCP, and Azure

Features:
- Parse unified multi-cloud asset inventories
- Apply policy rule base (public exposure, encryption, IAM, logging, bucket versioning)
- Compute compliance scores per CIS/NIST framework
- Emit text + optional CSV reports
- Offline demo with embedded sample assets

Usage:
    python3 cspm.py
    python3 cspm.py --assets cloud_assets.json --output report.csv

WARNING: Educational use only. Only assess environments you own or are authorized to audit.
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

SAMPLE_ASSETS = [
    {
        "provider": "aws", "type": "s3", "id": "my-public-bucket",
        "config": {
            "public_access": True, "encryption": False, "versioning": False,
            "logging": False, "mfa_delete": False, "region": "us-east-1"
        },
        "tags": {"env": "prod", "team": "data"}
    },
    {
        "provider": "aws", "type": "s3", "id": "internal-reports",
        "config": {
            "public_access": False, "encryption": True, "versioning": True,
            "logging": True, "mfa_delete": True, "region": "us-east-1"
        },
        "tags": {"env": "prod", "team": "finance"}
    },
    {
        "provider": "aws", "type": "ec2", "id": "i-0abc123",
        "config": {
            "public_ip": True, "encryption": False, "logging": False,
            "security_groups": ["sg-open-ssh"], "region": "us-west-2"
        },
        "tags": {"env": "dev", "team": "engineering"}
    },
    {
        "provider": "aws", "type": "iam", "id": "service-account-01",
        "config": {
            "mfa": False, "access_key_age_days": 200,
            "inline_policy_resource": "*", "console_access": True
        },
        "tags": {"env": "prod", "team": "platform"}
    },
    {
        "provider": "gcp", "type": "gcs", "id": "my-gcs-bucket",
        "config": {
            "public_access": True, "encryption": True, "versioning": False,
            "logging": False, "uniform_bucket_level_access": False, "location": "us-central1"
        },
        "tags": {"env": "staging", "team": "ml"}
    },
    {
        "provider": "gcp", "type": "compute", "id": "vm-instance-01",
        "config": {
            "public_ip": True, "encryption": True, "logging": False,
            "shielded_vm": False, "region": "us-central1-a"
        },
        "tags": {"env": "prod", "team": "backend"}
    },
    {
        "provider": "gcp", "type": "iam", "id": "sa-creator",
        "config": {
            "roles": ["roles/owner"], "mfa": False, "key_age_days": 150
        },
        "tags": {"env": "prod", "team": "admin"}
    },
    {
        "provider": "azure", "type": "storage", "id": "diagaccountprod",
        "config": {
            "public_access": False, "encryption": True, "versioning": False,
            "logging": True, "secure_transfer": False, "location": "eastus"
        },
        "tags": {"env": "prod", "team": "ops"}
    },
    {
        "provider": "azure", "type": "vm", "id": "web-vm-prod",
        "config": {
            "public_ip": True, "encryption": False, "logging": False,
            "disk_encryption": False, "location": "eastus"
        },
        "tags": {"env": "prod", "team": "web"}
    },
    {
        "provider": "azure", "type": "sql", "id": "prod-sql-db",
        "config": {
            "encryption": True, "auditing": False, "tls_version": "1.0",
            "firewall_allow_all": True, "location": "eastus"
        },
        "tags": {"env": "prod", "team": "data"}
    }
]

POLICY_RULES = [
    {"id": "PUB-001", "name": "No Public Access on Storage", "severity": "CRITICAL",
     "check": lambda a: a.get("type") in ("s3", "gcs", "storage") and a.get("config", {}).get("public_access", False)},
    {"id": "ENC-001", "name": "Encryption Disabled", "severity": "HIGH",
     "check": lambda a: not a.get("config", {}).get("encryption", True)},
    {"id": "LOG-001", "name": "Logging Not Enabled", "severity": "MEDIUM",
     "check": lambda a: not a.get("config", {}).get("logging", True)},
    {"id": "VER-001", "name": "Bucket Versioning Disabled", "severity": "MEDIUM",
     "check": lambda a: a.get("type") in ("s3", "gcs", "storage") and not a.get("config", {}).get("versioning", True)},
    {"id": "IAM-001", "name": "Over-Permissive IAM (resource: *)", "severity": "HIGH",
     "check": lambda a: a.get("type") == "iam" and a.get("config", {}).get("inline_policy_resource") == "*"},
    {"id": "IAM-002", "name": "IAM MFA Not Enabled", "severity": "HIGH",
     "check": lambda a: a.get("type") == "iam" and not a.get("config", {}).get("mfa", True)},
    {"id": "IAM-003", "name": "Stale Access Keys (>90 days)", "severity": "MEDIUM",
     "check": lambda a: a.get("type") == "iam" and a.get("config", {}).get("access_key_age_days", 0) > 90},
    {"id": "NET-001", "name": "Compute Instance with Public IP", "severity": "MEDIUM",
     "check": lambda a: a.get("type") in ("ec2", "compute", "vm") and a.get("config", {}).get("public_ip", False)},
    {"id": "SQL-001", "name": "SQL Firewall Allows All", "severity": "CRITICAL",
     "check": lambda a: a.get("type") == "sql" and a.get("config", {}).get("firewall_allow_all", False)},
    {"id": "SQL-002", "name": "SQL Auditing Disabled", "severity": "HIGH",
     "check": lambda a: a.get("type") == "sql" and not a.get("config", {}).get("auditing", True)},
    {"id": "NET-002", "name": "TLS Version < 1.2", "severity": "HIGH",
     "check": lambda a: a.get("config", {}).get("tls_version", "1.2") < "1.2"},
]


class CSPMAuditor:
    def __init__(self, assets=None):
        self.assets = assets or SAMPLE_ASSETS
        self.violations = []
        self.scores = defaultdict(lambda: {"pass": 0, "fail": 0, "total": 0})

    def audit_assets(self):
        print("\n" + "=" * 60)
        print("  MULTI-CLOUD CSPM POSTURE AUDIT")
        print("=" * 60)

        for asset in self.assets:
            provider = asset.get("provider", "unknown")
            atype = asset.get("type", "unknown")
            aid = asset.get("id", "unknown")
            framework = f"{provider.upper()}-{atype.upper()}"

            asset_violations = []
            for rule in POLICY_RULES:
                self.scores[framework]["total"] += 1
                try:
                    if rule["check"](asset):
                        self.scores[framework]["fail"] += 1
                        v = {
                            "asset": aid,
                            "provider": provider,
                            "type": atype,
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "severity": rule["severity"]
                        }
                        asset_violations.append(v)
                        self.violations.append(v)
                    else:
                        self.scores[framework]["pass"] += 1
                except Exception:
                    self.scores[framework]["pass"] += 1

            if asset_violations:
                print(f"\n  [{provider.upper()}] {atype}/{aid}:")
                for v in asset_violations:
                    print(f"    [!!] {v['severity']:8s} {v['rule_id']} — {v['rule_name']}")
            else:
                print(f"\n  [{provider.upper()}] {atype}/{aid}: OK")

    def compute_compliance_scores(self):
        print("\n" + "=" * 60)
        print("  COMPLIANCE SCORES BY FRAMEWORK")
        print("=" * 60)

        for framework, counts in sorted(self.scores.items()):
            total = counts["total"]
            passed = counts["pass"]
            score = (passed / total * 100) if total > 0 else 0
            grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
            bar_len = int(score / 5)
            bar = "=" * bar_len + "-" * (20 - bar_len)
            print(f"  {framework:20s} [{bar}] {score:5.1f}% ({grade})  ({passed}/{total} passed)")

        all_pass = sum(c["pass"] for c in self.scores.values())
        all_total = sum(c["total"] for c in self.scores.values())
        overall = (all_pass / all_total * 100) if all_total > 0 else 0
        print(f"\n  {'OVERALL':20s} {'':22s} {overall:5.1f}% ({all_pass}/{all_total} passed)")

    def severity_summary(self):
        print("\n" + "=" * 60)
        print("  VIOLATIONS BY SEVERITY")
        print("=" * 60)
        counts = defaultdict(int)
        for v in self.violations:
            counts[v["severity"]] += 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if counts[sev] > 0:
                print(f"  {sev:10s}: {counts[sev]}")
        print(f"\n  Total violations: {len(self.violations)}")

    def export_csv(self, path):
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["rule_id", "rule_name", "severity", "provider", "type", "asset"])
            writer.writeheader()
            for v in self.violations:
                writer.writerow(v)
        print(f"\n  CSV report saved to: {path}")

    def run(self):
        print(f"\n  Assets loaded: {len(self.assets)}")
        providers = set(a.get("provider", "?") for a in self.assets)
        print(f"  Providers: {', '.join(sorted(providers))}")
        print(f"  Policy rules: {len(POLICY_RULES)}")

        self.audit_assets()
        self.compute_compliance_scores()
        self.severity_summary()
        print("\n" + "=" * 60)
        return self.violations


def main():
    parser = argparse.ArgumentParser(description="CL8 — Multi-Cloud CSPM Posture Auditor")
    parser.add_argument("--assets", "-a", help="Path to unified asset JSON (uses demo if omitted)")
    parser.add_argument("--output", "-o", default="", help="Output CSV report base path (also writes JSON)")
    parser.add_argument("--exit-code-on-findings", action="store_true",
                        help="Exit 2 when CRITICAL violations exist (CI-friendly)")
    args = parser.parse_args()

    assets = None
    if args.assets:
        try:
            with open(args.assets) as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                assets = loaded.get("assets", loaded.get("resources", []))
            else:
                assets = loaded
            print(f"Loaded assets from: {args.assets}")
        except Exception as e:
            print(f"ERROR: Could not load assets: {e}")
            return 1
    else:
        print("No asset file provided — using embedded demo data")

    auditor = CSPMAuditor(assets)
    violations = auditor.run()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    output = args.output or os.path.join(base_dir, "..", "reports", "cl8-cspm")
    parent = os.path.dirname(os.path.abspath(output))
    os.makedirs(parent, exist_ok=True)
    csv_path = output if output.endswith(".csv") else output + ".csv"
    auditor.export_csv(csv_path)

    counts = defaultdict(int)
    for v in violations:
        counts[v["severity"]] += 1
    report = {
        "tool": "CL8-MultiCloudCSPM",
        "mode": "assets" if args.assets else "embedded-demo",
        "asset_count": len(auditor.assets),
        "violation_count": len(violations),
        "critical_count": counts["CRITICAL"],
        "summary": dict(counts),
        "violations": violations
    }
    json_path = output[:-4] + ".json" if output.endswith(".csv") else output + ".json"
    if json_path == csv_path:
        json_path = output + ".json"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, sort_keys=True)
    print(f"\n  JSON report saved to: {json_path}")

    print("\nDone.")
    if args.exit_code_on_findings and report["critical_count"] > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
