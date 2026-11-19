#!/usr/bin/env python3
"""
azure-defender-recommendations-auditor: audits real Microsoft Defender
for Cloud assessment and secure-score-control exports.
"""
import argparse
import json
import sys

from defender_parser import load_assessments, load_secure_score_controls
from checks import run_all

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def render_console(findings):
    if not findings:
        return "No findings - all checks passed."
    lines = []
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity), reverse=True):
        lines.append(f"[{f.severity.upper():<8}] {f.check_id}: {f.message}")
    return "\n".join(lines)


def to_json(findings):
    return [{"check_id": f.check_id, "severity": f.severity, "message": f.message} for f in findings]


def main():
    ap = argparse.ArgumentParser(description="Audit Microsoft Defender for Cloud exports")
    ap.add_argument("--assessments", required=True, help="Microsoft.Security/assessments export (JSON)")
    ap.add_argument("--secure-score-controls", required=True, help="Microsoft.Security/secureScoreControls export (JSON)")
    ap.add_argument("--json", metavar="PATH")
    ap.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "any"], default=None)
    args = ap.parse_args()

    with open(args.assessments) as fh:
        assessments = load_assessments(json.load(fh))
    with open(args.secure_score_controls) as fh:
        controls = load_secure_score_controls(json.load(fh))

    findings = run_all(assessments, controls)

    print(render_console(findings))
    print(f"\n{len(findings)} finding(s).")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(to_json(findings), fh, indent=2)

    if args.fail_on:
        trigger_idx = 0 if args.fail_on == "any" else SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f.severity) >= trigger_idx for f in findings):
            sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
