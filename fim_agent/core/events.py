"""Event handling for file system changes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Literal, Tuple, Optional, TYPE_CHECKING
import getpass

if TYPE_CHECKING:
    from fim_agent.core.config import Config


EventType = Literal["create", "modify", "delete", "rename", "move_internal", "move_in", "move_out"]
Severity = Literal["low", "medium", "high"]

# High-risk executable file extensions
HIGH_RISK_EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys",
    ".ps1", ".bat", ".cmd",
    ".vbs", ".js", ".jar",
}


@dataclass
class Event:
    timestamp: datetime
    event_type: EventType
    path: str
    old_hash: str | None
    new_hash: str | None
    severity: Severity
    mitre_tags: List[str]
    message: str
    # Extended contextual fields (optional)
    user: Optional[str] = None
    user_type: Optional[str] = "unknown"
    process_name: Optional[str] = None
    sha256: Optional[str] = None
    previous_sha256: Optional[str] = None
    hash_changed: Optional[bool] = None
    content_classification: Optional[str] = "public"
    classification_matches: Optional[List[str]] = None  # Keywords that matched for classification
    risk_score: Optional[int] = None
    ai_classification: Optional[str] = None
    ai_risk_score: Optional[int] = None
    ai_risk_reason: Optional[str] = None
    is_alert: Optional[bool] = None
    old_path: Optional[str] = None  # For rename events: the original path before rename
    requires_admin_approval: Optional[bool] = None  # True if event requires admin approval
    admin_approved: Optional[bool] = None  # True if admin has approved this event
    content_score: Optional[int] = None  # Content inspection risk score
    content_flags: Optional[List[str]] = None  # Content inspection flags
    ai_recommendation: Optional[str] = None  # AI-driven recommendation based on content
    first_seen: Optional[bool] = None  # True if this is the first time we observe this file path
    # Sticky privacy / effective classification (optional, nullable; for UI/debugging)
    sticky_private: Optional[bool] = None
    effective_classification: Optional[str] = None


def calculate_severity(path: str) -> Severity:
    """Assign a coarse severity based on file type."""
    lower_path = path.lower()
    sensitive_exts = {".ps1", ".sh", ".bat", ".py", ".dll", ".exe", ".so", ".sys"}
    config_exts = {".conf", ".ini", ".yaml", ".yml", ".json"}

    if any(lower_path.endswith(ext) for ext in sensitive_exts):
        return "high"
    if any(lower_path.endswith(ext) for ext in config_exts):
        return "medium"
    return "low"


def derive_severity_from_risk(risk_score: Optional[int]) -> Severity:
    """
    Derive severity from risk score.
    High for >= 80, medium for >= 50, low otherwise.
    """
    if risk_score is None:
        return "low"
    if risk_score >= 80:
        return "high"
    elif risk_score >= 50:
        return "medium"
    return "low"


def map_mitre_tags(path: str, event_type: EventType) -> List[str]:
    """Return simple MITRE-like tags based on path and event type."""
    tags: List[str] = []
    lower_path = path.lower()

    if event_type == "delete":
        tags.append("Defense Evasion")
    if event_type == "modify":
        tags.append("Tampering")
    if event_type in ("rename", "move_internal", "move_in", "move_out"):
        tags.append("Defense Evasion")
        # Add Persistence tag for sensitive paths
        sensitive_dirs = ("secure", "etc", "system32", "windows", "boot", "config")
        if any(part in lower_path for part in sensitive_dirs):
            tags.append("Persistence")
        # Move_out is particularly suspicious (data exfiltration)
        if event_type == "move_out":
            tags.append("Exfiltration")
    if any(lower_path.endswith(ext) for ext in (".ps1", ".sh", ".bat", ".py")):
        tags.append("Execution")
    if any(lower_path.endswith(ext) for ext in (".conf", ".ini", ".yaml", ".yml", ".json")):
        tags.append("Config Manipulation")

    # Ensure tags are unique and stable
    return list(dict.fromkeys(tags))


def infer_user() -> Optional[str]:
    """Best-effort inference of acting user."""
    try:
        return getpass.getuser()
    except Exception:
        return "fim"


def infer_user_type(user: Optional[str]) -> str:
    """Roughly classify user as system/human/unknown."""
    if not user:
        return "unknown"
    system_like = {"root", "system", "svc", "service", "daemon"}
    lowered = user.lower()
    if any(token in lowered for token in system_like):
        return "system"
    return "human"


def simple_risk_score(event: Event) -> int:
    """Assign a simple risk score based on event characteristics."""
    score = 10
    if event.event_type == "delete":
        score += 25
    elif event.event_type == "rename":
        score += 20  # Renames can be used to evade detection
    elif event.event_type == "move_internal":
        score += 22  # Internal moves may indicate organization/evasion
    elif event.event_type == "move_in":
        score += 30  # Files moving into monitored area are suspicious
    elif event.event_type == "move_out":
        score += 35  # Files leaving monitored area (potential exfiltration)
    if event.severity == "high":
        score += 30
    elif event.severity == "medium":
        score += 15

    lower_path = event.path.lower()
    sensitive_exts = (".ps1", ".sh", ".bat", ".py", ".dll", ".exe", ".so", ".sys")
    config_exts = (".conf", ".ini", ".yaml", ".yml", ".json")
    sensitive_dirs = ("secure", "etc", "system32", "windows", "boot")

    if lower_path.endswith(sensitive_exts) or lower_path.endswith(config_exts):
        score += 15
    if any(part in lower_path for part in sensitive_dirs):
        score += 10
    if event.hash_changed:
        score += 10
    
    # Add content inspection score if available
    if event.content_score is not None:
        score += event.content_score
    
    # High-risk executable/DLL handling for create/modify events
    if event.event_type in ("create", "modify"):
        # Check if path ends with a high-risk executable extension (case-insensitive)
        path_lower = event.path.lower()
        is_executable = any(path_lower.endswith(ext.lower()) for ext in HIGH_RISK_EXECUTABLE_EXTENSIONS)
        
        if is_executable:
            # Ensure risk_score is at least 80
            score = max(score, 80)
            
            # Initialize content_flags if needed
            if event.content_flags is None:
                event.content_flags = []
            
            # Append "executable_drop" only once
            if "executable_drop" not in event.content_flags:
                event.content_flags.append("executable_drop")
            
            # Initialize mitre_tags if needed (should already be set, but be safe)
            if event.mitre_tags is None:
                event.mitre_tags = []
            
            # Add "Execution" and "Defense Evasion" if not already present
            if "Execution" not in event.mitre_tags:
                event.mitre_tags.append("Execution")
            if "Defense Evasion" not in event.mitre_tags:
                event.mitre_tags.append("Defense Evasion")
    
    # High-risk: Tampering with private/secret files
    # Import TAMPER_EVENTS here to avoid circular import
    from fim_agent.core.governance import TAMPER_EVENTS
    
    if event.event_type in TAMPER_EVENTS:
        if event.content_classification == "secret":
            # Secret file tampering is critical
            score = max(score, 90)
        elif event.content_classification == "private":
            # Private file tampering is high-risk
            score = max(score, 80)
    
    return min(score, 100)


def simple_ai_classification(event: Event) -> Tuple[str, int, str]:
    """
    Return a lightweight, rule-based "AI" classification.

    This is a placeholder for a real model; currently rule-based.
    """
    base_score = simple_risk_score(event)
    reason_parts = [f"user_type={event.user_type}"]
    
    # Include content flags in AI reasoning if present
    if event.content_flags:
        reason_parts.append(f"content_flags={','.join(event.content_flags[:3])}")  # Limit to first 3 flags
    
    reason = f"local rule model: {', '.join(reason_parts)}"
    classification = "public"
    if base_score >= 70:
        classification = "sensitive"
    elif base_score >= 40:
        classification = "internal"
    
    # Generate AI recommendation based on content flags
    recommendation = None
    if event.content_flags:
        if "suspicious_base64" in event.content_flags:
            recommendation = "Review: Multiple base64 strings detected - potential obfuscation"
        elif any("kw:" in flag for flag in event.content_flags):
            recommendation = "Review: Suspicious keywords detected in file content"
        elif any("extension:" in flag for flag in event.content_flags):
            ext_flags = [f for f in event.content_flags if "extension:" in f]
            if ext_flags:
                recommendation = f"Review: Executable/script file type detected ({ext_flags[0]})"
    
    if recommendation:
        event.ai_recommendation = recommendation
    
    return classification, base_score, reason


def mark_alert(event: Event, min_risk: int, min_ai_risk: int) -> Event:
    """
    Mark an event as an alert based on risk score thresholds.
    
    Sets event.is_alert = True if:
    - event.risk_score is not None and >= min_risk, OR
    - event.ai_risk_score is not None and >= min_ai_risk, OR
    - Tamper event on private/secret file that is NOT first-seen (forced alert)
    
    CREATE events on private files do NOT trigger alerts (first-seen is allowed).
    Tamper events on existing private files DO trigger alerts.
    
    Otherwise sets is_alert = False.
    """
    from fim_agent.core.governance import TAMPER_EVENTS
    
    is_alert = False
    
    # Check if file is private/secret
    is_private = event.content_classification in ("private", "secret")
    
    # Detect first-seen: previous_sha256 is None OR first_seen is True
    is_first_seen = (
        event.previous_sha256 is None or 
        (event.first_seen is not None and event.first_seen is True)
    )
    
    # Force alert for tamper events on private/secret files that are NOT first-seen
    if event.event_type in TAMPER_EVENTS:
        if is_private and not is_first_seen:
            is_alert = True
            event.is_alert = is_alert
            return event
    
    # CREATE events on private files: do NOT force alert (allow first-seen)
    # This is handled by the standard risk-based logic below
    
    # Standard risk-based alert logic
    if event.risk_score is not None and event.risk_score >= min_risk:
        is_alert = True
    elif event.ai_risk_score is not None and event.ai_risk_score >= min_ai_risk:
        is_alert = True
    
    event.is_alert = is_alert
    return event


def mark_requires_admin_approval(
    event: Event,
    require_admin: bool,
    admin_min_risk: int,
    admin_min_ai_risk: int,
    config: Optional["Config"] = None,
) -> Event:
    """
    Mark an event as requiring admin approval based on governance policy.
    
    This is a wrapper that respects the require_admin flag and calls
    the governance module's mark_requires_admin_approval function.
    
    Note: This function is kept for backward compatibility, but watcher.py
    now calls governance.mark_requires_admin_approval directly.
    """
    from fim_agent.core.governance import mark_requires_admin_approval as gov_mark_approval
    
    if not require_admin:
        event.requires_admin_approval = False
        event.admin_approved = None
        return event
    
    # Call the governance function
    gov_mark_approval(event, config)
    return event


__all__ = [
    "Event",
    "calculate_severity",
    "derive_severity_from_risk",
    "map_mitre_tags",
    "infer_user",
    "infer_user_type",
    "simple_risk_score",
    "simple_ai_classification",
    "mark_alert",
    "mark_requires_admin_approval",
    "EventType",
    "Severity",
    "HIGH_RISK_EXECUTABLE_EXTENSIONS",
]

