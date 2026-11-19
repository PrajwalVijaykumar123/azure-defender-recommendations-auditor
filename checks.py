"""
5 checks over Defender for Cloud's two real data sources.

CRITICAL_RECOMMENDATIONS is a deliberate, documented override: Defender
for Cloud ships its own severity label per recommendation (High/Medium/
Low), but a real security team doesn't treat every "Medium" the same -
a handful of specific recommendations (MFA on privileged accounts,
storage secure-transfer, disk encryption) are treated as critical
regardless of the vendor's own label, because the blast radius of
leaving them unhealthy is disproportionate to a generic "Medium". This
mirrors how real teams actually triage vendor-provided severities
rather than following them blindly.
"""
from dataclasses import dataclass

HIGH_IMPACT_WEIGHT_THRESHOLD = 8.0
CONTROL_HEALTH_RATIO_THRESHOLD = 0.5
CATEGORY_UNHEALTHY_RATIO_THRESHOLD = 0.5
SECURE_SCORE_PCT_THRESHOLD = 60.0

CRITICAL_RECOMMENDATIONS = {
    "MFA should be enabled on accounts with owner permissions on subscriptions",
    "Secure transfer to storage accounts should be enabled",
    "Disk encryption should be applied on virtual machines",
}


@dataclass
class Finding:
    check_id: str
    severity: str
    message: str


def check_unhealthy_high_severity(assessments: list) -> list:
    return [
        Finding("AZD-1", "high",
                f"{a.resource_id}: '{a.display_name}' is Unhealthy (Defender severity: High).")
        for a in assessments
        if a.status_code == "Unhealthy" and a.severity == "High"
    ]


def check_overridden_critical_recommendations(assessments: list) -> list:
    return [
        Finding("AZD-2", "critical",
                f"{a.resource_id}: '{a.display_name}' is Unhealthy - treated as critical "
                f"regardless of Defender's own '{a.severity}' label, because of its "
                f"disproportionate blast radius if left unaddressed.")
        for a in assessments
        if a.status_code == "Unhealthy" and a.display_name in CRITICAL_RECOMMENDATIONS
    ]


def check_high_impact_secure_score_gaps(controls: list,
                                         weight_threshold: float = HIGH_IMPACT_WEIGHT_THRESHOLD,
                                         ratio_threshold: float = CONTROL_HEALTH_RATIO_THRESHOLD) -> list:
    findings = []
    for c in controls:
        if c.max <= 0:
            continue
        ratio = c.current / c.max
        if c.weight >= weight_threshold and ratio < ratio_threshold:
            findings.append(Finding(
                "AZD-3", "high",
                f"'{c.display_name}' is only {ratio*100:.0f}% healthy ({c.current:.1f}/{c.max:.1f}) "
                f"but carries a weight of {c.weight:.0f} - the highest-leverage secure-score gap to close.",
            ))
    return findings


def check_category_unhealthy_ratio(assessments: list,
                                    threshold: float = CATEGORY_UNHEALTHY_RATIO_THRESHOLD) -> list:
    totals = {}
    unhealthy = {}
    for a in assessments:
        for cat in a.categories:
            totals[cat] = totals.get(cat, 0) + 1
            if a.status_code == "Unhealthy":
                unhealthy[cat] = unhealthy.get(cat, 0) + 1
    findings = []
    for cat, total in totals.items():
        bad = unhealthy.get(cat, 0)
        ratio = bad / total
        if ratio >= threshold:
            findings.append(Finding(
                "AZD-4", "medium",
                f"Category '{cat}': {bad}/{total} assessments are Unhealthy "
                f"({ratio*100:.0f}%) - systemic gap in this category, not an isolated finding.",
            ))
    return findings


def check_overall_secure_score(controls: list, threshold: float = SECURE_SCORE_PCT_THRESHOLD) -> list:
    total_current = sum(c.current for c in controls)
    total_max = sum(c.max for c in controls)
    if total_max <= 0:
        return []
    pct = total_current / total_max * 100
    if pct < threshold:
        return [Finding(
            "AZD-5", "high",
            f"Overall secure score is {pct:.1f}% ({total_current:.1f}/{total_max:.1f}), "
            f"below the {threshold:.0f}% threshold.",
        )]
    return []


def run_all(assessments: list, controls: list) -> list:
    findings = []
    findings += check_unhealthy_high_severity(assessments)
    findings += check_overridden_critical_recommendations(assessments)
    findings += check_high_impact_secure_score_gaps(controls)
    findings += check_category_unhealthy_ratio(assessments)
    findings += check_overall_secure_score(controls)
    return findings
