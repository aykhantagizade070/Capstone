"""Governance rules for respecting privacy and data protection."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from fim_agent.core.config import Config
from fim_agent.core.events import Event

# Event types that represent tampering with existing files
TAMPER_EVENTS = {"modify", "delete", "rename", "move_internal", "move_out"}

# Module-level set to track paths that have been seen as sensitive
SENSITIVE_PATHS: set[str] = set()

# Grace window for "create -> immediate modify" noise (Notepad/Splunk davranışı)
CREATE_GRACE: dict[str, float] = {}
GRACE_SECONDS = 5


def _norm_path(path: str | Path | None) -> str:
    """Normalize a path to a canonical string representation."""
    if path is None:
        return ""
    try:
        return str(Path(path).resolve())
    except Exception:
        return str(path)


def is_sensitive(event: Event, config: Optional[Config] = None) -> bool:
    eff = getattr(event, "effective_classification", None)
    cls = (eff or event.content_classification or "").lower()

    # sticky_private varsa həmişə sensitive say
    if bool(getattr(event, "sticky_private", False)):
        return True

    if cls in ("private", "secret"):
        return True

    threshold = getattr(config, "admin_min_risk_score", 80) if config else 80
    return event.risk_score is not None and event.risk_score >= threshold


def mark_requires_admin_approval(event: Event, config: Optional[Config] = None) -> Event:
    """
    Admin approval rules:

    - CREATE: heç vaxt approval istəmir
    - create-dən dərhal sonra gələn modify (GRACE_SECONDS içində): approval istəmir (Notepad noise)
    - private/secret faylda sonrakı tamper: approval istəyir
    - high-risk tamper (risk_score >= admin_min_risk_score): approval istəyir
    """
    # Defaults
    event.requires_admin_approval = False
    event.admin_approved = None
    event.first_seen = False

    # If admin approval is globally disabled, no approval needed
    if not config or not getattr(config, "require_admin_for_alerts", True):
        return event

    # Only process CREATE and TAMPER_EVENTS
    if event.event_type != "create" and event.event_type not in TAMPER_EVENTS:
        return event

    key = _norm_path(event.path)
    was_sensitive = key in SENSITIVE_PATHS
    now_sensitive = is_sensitive(event, config)

    # -------------------------
    # CREATE: never require approval
    # -------------------------
    if event.event_type == "create":
        if now_sensitive and not was_sensitive:
            SENSITIVE_PATHS.add(key)
            event.first_seen = True
        elif now_sensitive and was_sensitive:
            event.first_seen = False
        else:
            event.first_seen = not was_sensitive

        event.requires_admin_approval = False
        event.admin_approved = None

        # mark grace start for this path (create -> immediate modify)
        CREATE_GRACE[key] = time.time()
        return event

    # -------------------------
    # TAMPER EVENTS
    # -------------------------
    if event.event_type in TAMPER_EVENTS:
        # 1) Grace: create-dən dərhal sonra gələn modify-ləri approval-a salma
        grace_t0 = CREATE_GRACE.get(key)
        if grace_t0 is not None:
            dt = time.time() - grace_t0
            if dt <= GRACE_SECONDS and event.event_type == "modify":
                # bu, yeni faylın "ilk yazılışı" kimi davransın
                if now_sensitive:
                    SENSITIVE_PATHS.add(key)
                event.first_seen = True
                event.requires_admin_approval = False
                event.admin_approved = None
                return event
            # grace keçibsə təmizlə
            if dt > GRACE_SECONDS:
                CREATE_GRACE.pop(key, None)

        # 2) sensitivity set update
        if not now_sensitive and was_sensitive:
            SENSITIVE_PATHS.discard(key)
            was_sensitive = False
        elif now_sensitive and not was_sensitive:
            SENSITIVE_PATHS.add(key)
            was_sensitive = True

        # 3) high risk check
        admin_min_risk = getattr(config, "admin_min_risk_score", 80)
        is_high_risk = event.risk_score is not None and event.risk_score >= admin_min_risk

        # 4) first-seen by baseline (brand new private file case)
        baseline_missing = getattr(event, "previous_sha256", None) is None

        # ---- Private/Sensitive tamper logic
        if now_sensitive:
            if baseline_missing:
                # ilk dəfə görürük / baseline yoxdu -> approval istəmə
                event.first_seen = True
                event.requires_admin_approval = False
                event.admin_approved = None
                return event

            # baseline var -> artıq tanınmış sensitive fayldır -> approval tələb et
            event.first_seen = False
            event.requires_admin_approval = True
            event.admin_approved = False
            return event

        # ---- Non-sensitive: only high-risk tamper requires approval
        if is_high_risk:
            event.first_seen = False
            event.requires_admin_approval = True
            event.admin_approved = False
            return event

        # ---- Low-risk non-sensitive tamper: no approval
        event.first_seen = False
        event.requires_admin_approval = False
        event.admin_approved = None
        return event

    return event


def is_tamper_event(event: Event) -> bool:
    return event.event_type in TAMPER_EVENTS


def generate_ai_recommendation(event: Event) -> str:
    recommendations = []

    if event.content_flags and "executable_drop" in event.content_flags:
        if event.event_type == "create":
            recommendations.append(
                "🚨 CRITICAL: New executable file detected. Verify source and scan for malware immediately."
            )
        elif event.event_type == "modify":
            recommendations.append(
                "🚨 CRITICAL: Executable file modified. Check for unauthorized code injection or updates."
            )

    if event.hash_changed:
        if event.event_type == "modify":
            recommendations.append(
                "⚠️ INTEGRITY VIOLATION: File hash changed. Compare with baseline to identify unauthorized modifications."
            )
        elif event.event_type in ("rename", "move_internal"):
            recommendations.append(
                "⚠️ File moved/renamed with hash change. Verify this is expected and not a substitution attack."
            )

    eff = getattr(event, "effective_classification", None)
    cls = (eff or event.content_classification or "").lower()
    sticky_private = bool(getattr(event, "sticky_private", False))
    is_priv = cls in ("private", "secret") or sticky_private

    if is_priv:
        if event.event_type in TAMPER_EVENTS:
            if event.requires_admin_approval and event.admin_approved is False:
                recommendations.append(
                    "🔒 SENSITIVE DATA TAMPERING: Private/secret file modified without admin approval. Review immediately and verify authorization."
                )
            else:
                recommendations.append(
                    "🔒 SENSITIVE DATA: Private/secret file accessed. Ensure proper authorization and audit access logs."
                )
        elif event.event_type == "create":
            recommendations.append(
                "🔒 SENSITIVE DATA CREATED: New file contains private/secret content. Verify data handling compliance."
            )

    if event.content_flags:
        if "suspicious_base64" in event.content_flags:
            recommendations.append(
                "🔍 SUSPICIOUS: Multiple base64-encoded strings detected. May indicate obfuscated payload - analyze content manually."
            )
        if any("kw:" in flag for flag in event.content_flags):
            suspicious_kws = [f.replace("kw:", "") for f in event.content_flags if "kw:" in f]
            recommendations.append(
                f"🔍 SUSPICIOUS KEYWORDS: Detected potentially malicious commands ({', '.join(suspicious_kws[:3])}). Review file content for script injection."
            )

    if event.risk_score is not None and event.risk_score >= 80:
        if event.event_type == "create":
            recommendations.append(
                "⚠️ HIGH RISK: New file with elevated risk score. Investigate source and purpose before allowing execution."
            )
        elif event.event_type == "modify":
            recommendations.append(
                "⚠️ HIGH RISK: File modification with elevated risk score. Verify changes are authorized and expected."
            )

    if event.event_type == "delete":
        if is_priv:
            recommendations.append(
                "🗑️ DATA LOSS RISK: Sensitive file deleted. Check if this is expected or potential data exfiltration/destruction."
            )
        elif event.risk_score is not None and event.risk_score >= 60:
            recommendations.append(
                "🗑️ HIGH-RISK DELETE: Important file removed. Verify deletion is authorized and check for backup."
            )
        else:
            recommendations.append("📋 ROUTINE: File deletion detected. Verify this is expected system maintenance.")

    if event.event_type in ("rename", "move_internal", "move_out"):
        if is_priv:
            recommendations.append("📁 SENSITIVE FILE MOVED: Verify move is authorized and destination is secure.")
        elif event.risk_score is not None and event.risk_score >= 60:
            recommendations.append("📁 HIGH-RISK FILE MOVED: Verify move is expected and not an evasion attempt.")
        else:
            recommendations.append("📋 ROUTINE: File moved/renamed. Verify this is expected system activity.")

    if event.first_seen:
        if is_priv:
            recommendations.append(
                "🆕 NEW SENSITIVE FILE: First observation of sensitive content. Classify and apply appropriate access controls."
            )
        elif event.risk_score is not None and event.risk_score >= 50:
            recommendations.append("🆕 NEW FILE: First observation with moderate risk. Verify source and purpose.")

    if event.requires_admin_approval:
        if event.admin_approved is False:
            recommendations.append("⏳ PENDING APPROVAL: Event requires admin approval. Review and approve if authorized.")
        elif event.admin_approved is True:
            recommendations.append("✅ APPROVED: Event has been reviewed and approved by administrator.")
        else:
            recommendations.append("⏳ PENDING APPROVAL: Approval status unknown. Refresh and verify event state.")

    if not recommendations:
        if event.event_type == "create":
            recommendations.append("📋 ROUTINE: New file created. Monitor for suspicious activity.")
        elif event.event_type == "modify":
            recommendations.append("📋 ROUTINE: File modified. Verify changes are expected.")
        else:
            recommendations.append("📋 ROUTINE: File system event detected. No immediate action required.")

    if len(recommendations) == 1:
        return recommendations[0]

    priority_order = ["🚨", "⚠️", "🔒", "🔍", "🗑️", "📁", "🆕", "⏳", "✅", "⚔️", "📋"]
    recommendations.sort(
        key=lambda r: (
            next((i for i, p in enumerate(priority_order) if r.startswith(p)), len(priority_order)),
            r,
        )
    )
    return recommendations[0] + " " + " | ".join(recommendations[1:3])


__all__ = [
    "is_sensitive",
    "is_tamper_event",
    "TAMPER_EVENTS",
    "mark_requires_admin_approval",
    "SENSITIVE_PATHS",
    "_norm_path",
    "generate_ai_recommendation",
]
