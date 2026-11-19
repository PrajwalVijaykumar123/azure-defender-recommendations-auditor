"""
Parsers for real Microsoft Defender for Cloud (Azure Security Center)
export shapes - two separate real resource types, fed by two separate
real APIs:

  - Microsoft.Security/assessments (`az security assessment list`):
      per-resource compliance status against a specific recommendation,
      e.g. "System updates should be installed on your machines" against
      one specific VM. Real shape:
      {
        "id": "...", "name": "<guid>",
        "properties": {
          "status": {"code": "Unhealthy"},
          "resourceDetails": {"Id": "/subscriptions/.../vm1"},
          "metadata": {
            "displayName": "System updates should be installed...",
            "severity": "Medium",
            "categories": ["Compute"]
          }
        }
      }

  - Microsoft.Security/secureScoreControls (`az security secure-scores
      list`/secureScoreControls): the real control-group breakdown behind
      the single "Secure Score" percentage shown on the Defender for Cloud
      overview page. Each control has its own weight and a current/max
      score - e.g. "Enable MFA" might be worth up to 10 points tenant-
      wide but currently sitting at 2 because most eligible accounts
      don't have it on. Real shape:
      {
        "name": "<guid>",
        "properties": {
          "displayName": "Enable MFA",
          "weight": 10,
          "score": {"current": 2.0, "max": 10.0}
        }
      }

As with this portfolio's other `az`-sourced tools, field placement can
drift between API versions (sometimes flattened, sometimes nested under
"properties") - `_get()` is the same defensive top-level-or-nested
lookup used in `azure-resource-security-auditor`, applied here again
because there is no live Azure subscription available to validate
against a specific API version.
"""
from dataclasses import dataclass


def _get(obj: dict, key: str, default=None):
    if key in obj:
        return obj[key]
    props = obj.get("properties", {})
    return props.get(key, default)


@dataclass
class Assessment:
    resource_id: str
    display_name: str
    status_code: str      # "Healthy" | "Unhealthy" | "NotApplicable"
    severity: str          # "High" | "Medium" | "Low"
    categories: list


@dataclass
class SecureScoreControl:
    display_name: str
    weight: float
    current: float
    max: float


def load_assessments(raw: list) -> list:
    out = []
    for a in raw:
        props = a.get("properties", a)
        status = props.get("status", {}) or {}
        metadata = props.get("metadata", {}) or {}
        resource = props.get("resourceDetails", {}) or {}
        out.append(Assessment(
            resource_id=resource.get("Id", a.get("id", "?")),
            display_name=metadata.get("displayName", "?"),
            status_code=status.get("code", "NotApplicable"),
            severity=metadata.get("severity", "Low"),
            categories=metadata.get("categories", []) or [],
        ))
    return out


def load_secure_score_controls(raw: list) -> list:
    out = []
    for c in raw:
        props = c.get("properties", c)
        score = props.get("score", {}) or {}
        out.append(SecureScoreControl(
            display_name=props.get("displayName", "?"),
            weight=float(props.get("weight", 0)),
            current=float(score.get("current", 0)),
            max=float(score.get("max", 0)),
        ))
    return out
