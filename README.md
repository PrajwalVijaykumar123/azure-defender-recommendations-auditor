# Azure Defender Recommendations Auditor

Audits real **Microsoft Defender for Cloud** exports - per-resource compliance assessments and the secure-score control breakdown behind the single "Secure Score" percentage on the Defender overview page - for **5 checks**, including a deliberate severity override for a short list of recommendations whose real-world blast radius outweighs Defender's own default label.

## Two Real Defender for Cloud Resources, Two Real Jobs

- **`Microsoft.Security/assessments`** - one row per resource per recommendation: is this specific VM's disk encrypted, is this specific NSG exposing management ports, etc. Each carries Defender's own `severity` (High/Medium/Low) and `categories` (Compute, Networking, Identity and access, Data, ...).
- **`Microsoft.Security/secureScoreControls`** - the control-group breakdown behind Secure Score itself. Each control (e.g. "Enable MFA") has a `weight` (how many points it's worth tenant-wide) and a `current`/`max` score - a control can be worth 10 points and currently sitting at 2 because most eligible resources are unhealthy against it.

These feed two different real UI surfaces in the Azure portal (the recommendations list, and the Secure Score breakdown) and a real audit has to look at both: a single Unhealthy assessment tells you about one resource, but the secure-score control tells you which *category* of gap is actually worth fixing first across the whole tenant.

## What This Project Checks

| ID | Check | Severity |
|---|---|---|
| AZD-1 | An assessment is Unhealthy and Defender's own severity is High | High |
| AZD-2 | An assessment is Unhealthy for one of a short list of recommendations (MFA on privileged accounts, storage secure-transfer, disk encryption) - **treated as critical regardless of Defender's own severity label** | Critical |
| AZD-3 | A secure-score control is below 50% healthy while carrying a weight of 8+ points - the highest-leverage gap to close | High |
| AZD-4 | A recommendation category (e.g. "Identity and access") has 50%+ of its assessments Unhealthy - a systemic gap, not an isolated finding | Medium |
| AZD-5 | The overall secure score (sum of all controls' current/max) is below 60% | High |

### Why AZD-2 Deliberately Overrides Defender's Own Severity

Defender labels "MFA should be enabled on accounts with owner permissions on subscriptions" as only **Medium** severity by default. A real security team doesn't take that label at face value - an unprotected subscription-owner account is a tenant-takeover risk, which is categorically worse than a generic Medium finding. `CRITICAL_RECOMMENDATIONS` in `checks.py` is a short, explicit, documented list of exactly the recommendations this portfolio treats this way, rather than a blanket "ignore the vendor's severity" rule - the override is scoped to specific, named, high-blast-radius controls.

## Relationship to This Portfolio's Other Azure Tool

**`azure-resource-security-auditor`** audits raw Azure resource configuration directly (NSG rules, Storage Account settings, Key Vault settings) via `az` CLI exports - it's a config-level auditor that doesn't need Defender for Cloud enabled at all. **This tool** audits Defender for Cloud's own *assessment layer* - the recommendations and secure score Defender itself computes *from* that configuration, plus tenant-wide prioritization data (control weights, category rollups) that a raw resource export doesn't carry. The two complement each other: one checks the resources, the other checks what the platform's own posture-management layer concluded about them.

## Tech Stack

- Python 3.11, standard library only (`dataclasses`, `argparse`, `json`) - no third-party dependencies

## Setup

```bash
python3 scanner.py --assessments assessments.json --secure-score-controls controls.json
python3 scanner.py --assessments assessments.json --secure-score-controls controls.json --json report.json --fail-on critical
```

## Testing

`test_fixtures/` has a compliant pair (all assessments Healthy, all controls near-max score) and a noncompliant pair exercising all 5 checks: a High-severity Unhealthy networking assessment, an Unhealthy MFA assessment that triggers the critical override, a second Unhealthy Identity-and-access assessment that pushes that category over the 50% systemic-gap threshold, an "Enable MFA" secure-score control sitting at 20% health despite a weight of 10, and an overall secure score of 43.8% - below the 60% threshold. `run_test.sh` runs the real scanner against both:

```bash
sh test_fixtures/run_test.sh
```

9 assertions, all passing - including one confirming `AZD-4` fires independently for **both** affected categories (Networking and Identity and access), not just the first one found.

## Architecture

```
scanner.py (CLI: severity-sorted report, JSON output, --fail-on exit codes)
        |
        v
defender_parser.py: loads 2 real Defender for Cloud export shapes
    (Assessment / SecureScoreControl), defensively handling top-level-
    or-properties-nested field placement across API versions
        |
        v
checks.py: 5 checks, including the documented CRITICAL_RECOMMENDATIONS
    severity override
        |
        v
Console report (grouped by severity) + optional JSON; exit code reflects --fail-on
```

## Project Structure

```
azure-defender-recommendations-auditor/
├── scanner.py                                  # CLI
├── defender_parser.py                          # 2 real Defender export-shape loaders
├── checks.py                                   # 5 checks incl. severity override list
└── test_fixtures/
    ├── compliant_assessments.json
    ├── compliant_secure_score_controls.json
    ├── noncompliant_assessments.json
    ├── noncompliant_secure_score_controls.json
    └── run_test.sh                             # Runs scanner.py against both pairs
```

## What I Learned

- A vendor's own severity label is a starting point, not the final word - building AZD-2 required deciding, explicitly and in writing, which specific recommendations this portfolio considers disproportionately dangerous even at Defender's "Medium" rating, rather than writing a vague "upgrade anything security-related" rule that would just as easily have fired on something unimportant.
- The secure-score control's `weight` field is what actually tells you where to focus - two controls can both be "unhealthy," but one worth 10 points tenant-wide and one worth 1 point are not equally worth a security engineer's next hour. AZD-3 specifically requires both a low health ratio AND a high weight together, because either alone is a much weaker signal (a low-weight control being unhealthy barely moves the needle; a high-weight control that's merely slightly under 100% isn't urgent either).
- Designing the noncompliant fixture to make AZD-4 fire for two *different* categories simultaneously (rather than accidentally testing only one) meant deliberately spreading the Unhealthy assessments across "Networking" and "Identity and access" and writing a test assertion that checks for exactly 2 AZD-4 findings, not just "at least 1" - a weaker assertion would have passed even if the per-category grouping logic were silently broken.

## Next Steps

- Live Graph/Azure REST integration (`az security assessment list` / `az security secure-scores list`, or the equivalent Python SDK calls) so this could run as a real scheduled posture check against an actual subscription.
- A `--trend` mode comparing two exports taken at different times, to show whether the secure score and specific controls are improving or regressing - a single snapshot (what this version does) can't show direction.
- Feed this tool's findings into `bsi-compliance-aggregator` as a sixth adapter - Azure posture-management findings map naturally onto several existing Bausteine (`NET.3.2` for networking findings, `ORP.4` for identity findings), already used by other tools in this portfolio.
