"""Logging helpers for FIM Agent."""

from __future__ import annotations

import json
import logging
import socket
import sys
from pathlib import Path
from typing import Any, Dict

from fim_agent.core.config import Config
from fim_agent.core.events import Event
from fim_agent.core.config import _project_root


def _event_to_dict(event: Event, wazuh_format: bool = False) -> Dict[str, Any]:
    """Convert Event to structured dict for JSON logging."""
    if wazuh_format:
        # Wazuh-friendly format with standard fields
        payload = {
            "@timestamp": event.timestamp.isoformat(),
            "agent": {
                "name": "fim_agent",
                "id": "fim-agent-001",
            },
            "fim": {
                "event_type": event.event_type,
                "file": {
                    "path": event.path,
                    "sha256": event.sha256,
                    "previous_sha256": event.previous_sha256,
                    "hash_changed": event.hash_changed,
                },
                "user": {
                    "name": event.user,
                    "type": event.user_type,
                },
                "process": {
                    "name": event.process_name,
                },
                "classification": {
                    "content": event.content_classification,
                    "ai": event.ai_classification,
                },
                "risk": {
                    "score": event.risk_score,
                    "ai_score": event.ai_risk_score,
                    "content_score": event.content_score,
                },
                "severity": event.severity,
                "alert": event.is_alert if event.is_alert is not None else False,
                "admin_approval": {
                    "required": event.requires_admin_approval if event.requires_admin_approval is not None else False,
                    "approved": event.admin_approved if event.admin_approved is not None else None,
                },
                "message": event.message,
            },
            "rule": {
                "id": f"fim_{event.event_type}",
                "level": 5 if event.severity == "high" else (3 if event.severity == "medium" else 1),
                "description": event.message,
                "mitre": {
                    "id": event.mitre_tags if event.mitre_tags else [],
                },
            },
        }
        # Add optional fields
        if event.old_path:
            payload["fim"]["file"]["old_path"] = event.old_path
        if event.content_flags:
            payload["fim"]["content_flags"] = event.content_flags
        if event.classification_matches:
            payload["fim"]["classification"]["matches"] = event.classification_matches
        if event.ai_recommendation:
            payload["fim"]["recommendation"] = event.ai_recommendation
        if event.first_seen is not None:
            payload["fim"]["first_seen"] = event.first_seen
        return payload
    else:
        # Standard JSON format (SIEM/Wazuh-friendly)
        # Calculate rule level based on severity and risk_score
        rule_level = 3  # Default: low
        if event.severity == "high":
            rule_level = 12
        elif event.severity == "medium":
            rule_level = 7
        elif event.severity == "low":
            rule_level = 3
        
        # Adjust rule level based on risk_score if available
        if event.risk_score is not None:
            if event.risk_score >= 80:
                rule_level = max(rule_level, 12)  # High/Critical
            elif event.risk_score >= 50:
                rule_level = max(rule_level, 7)  # Medium
        
        # Determine rule ID based on risk level
        if event.risk_score is not None and event.risk_score >= 80:
            rule_id = 900001  # High-risk events
        else:
            rule_id = 900000  # Normal events
        
        payload = {
            # SIEM/Wazuh-friendly top-level fields
            "source": "fim_agent",
            "category": "file_integrity",
            "host": socket.gethostname(),
            "rule": {
                "id": rule_id,
                "level": rule_level,
                "description": _get_rule_description(event),
            },
            "mitre_techniques": event.mitre_tags if event.mitre_tags else [],
            # Existing fields (keep all for backward compatibility)
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "file_path": event.path,
            "user": event.user,
            "user_type": event.user_type,
            "process_name": event.process_name,
            "sha256": event.sha256,
            "previous_sha256": event.previous_sha256,
            "hash_changed": event.hash_changed,
            "content_classification": event.content_classification,
            "classification_matches": event.classification_matches,
            "risk_score": event.risk_score,
            "ai_classification": event.ai_classification,
            "ai_risk_score": event.ai_risk_score,
            "ai_risk_reason": event.ai_risk_reason,
            "severity": event.severity,
            "mitre_tags": event.mitre_tags,  # Keep for backward compatibility
            "message": event.message,
            "alert": event.is_alert if event.is_alert is not None else False,
            "requires_admin_approval": event.requires_admin_approval if event.requires_admin_approval is not None else False,
            "admin_approved": event.admin_approved if event.admin_approved is not None else None,
            "content_score": event.content_score,
            "content_flags": event.content_flags,
            "ai_recommendation": event.ai_recommendation,
            "first_seen": event.first_seen,
        }
        # Add old_path for rename events
        if event.old_path:
            payload["old_path"] = event.old_path
        return payload


def _get_rule_description(event: Event) -> str:
    """Generate a human-readable rule description based on event characteristics."""
    parts = []
    
    if event.risk_score is not None and event.risk_score >= 80:
        parts.append("High-risk")
    elif event.risk_score is not None and event.risk_score >= 50:
        parts.append("Medium-risk")
    else:
        parts.append("File integrity")
    
    if event.content_classification in ("private", "secret"):
        parts.append("sensitive content")
    elif event.content_flags and "executable_drop" in event.content_flags:
        parts.append("executable file")
    
    parts.append("event")
    
    return " ".join(parts).capitalize()


class JsonEventFormatter(logging.Formatter):
    """JSON formatter that serializes dict or Event messages."""

    def __init__(self, wazuh_format: bool = False):
        super().__init__()
        self.wazuh_format = wazuh_format

    def format(self, record: logging.LogRecord) -> str:
        msg = record.msg
        if isinstance(msg, Event):
            payload = _event_to_dict(msg, wazuh_format=self.wazuh_format)
        elif isinstance(msg, dict):
            payload = msg
        else:
            payload = {"message": str(msg)}
        return json.dumps(payload, ensure_ascii=False)


class TextEventFormatter(logging.Formatter):
    """Text formatter for human-readable logs."""

    def format(self, record: logging.LogRecord) -> str:
        return str(record.msg)


def setup_logging(config: Config) -> logging.Logger:
    """Configure logging according to config.log_format."""
    logger = logging.getLogger("fim_agent")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    root = _project_root()
    log_path = Path(config.log_file)
    if not log_path.is_absolute():
        log_path = root / log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)

    stream_handler = logging.StreamHandler(sys.stdout)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")

    if config.log_format == "wazuh":
        formatter = JsonEventFormatter(wazuh_format=True)
    elif config.log_format == "json":
        formatter = JsonEventFormatter(wazuh_format=False)
    else:
        formatter = TextEventFormatter()

    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    return logger


def get_logger(name: str = "fim_agent") -> logging.Logger:
    """
    Get a configured logger instance.
    
    If the "fim_agent" logger has been configured via setup_logging(),
    child loggers (e.g., "fim_agent.core.ai_client") will automatically
    propagate messages to the parent logger's handlers. Otherwise, a
    basic handler is added as a fallback.
    
    Args:
        name: Logger name (default: "fim_agent")
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Check if the root "fim_agent" logger has handlers configured
    root_logger = logging.getLogger("fim_agent")
    
    # If this is the root logger and it has handlers, we're done
    if name == "fim_agent" and root_logger.handlers:
        return logger
    
    # If this is a child logger (e.g., "fim_agent.core.ai_client"),
    # it will automatically propagate to the parent "fim_agent" logger
    # if the parent has handlers configured. We don't need to add
    # handlers to child loggers in that case.
    # 
    # Only add a fallback handler if:
    # 1. The root logger has no handlers (setup_logging hasn't been called), AND
    # 2. This logger itself has no handlers
    if not root_logger.handlers and not logger.handlers:
        # Add a basic stream handler to avoid "No handlers" warnings
        # This is a fallback if setup_logging hasn't been called
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(TextEventFormatter())
        logger.addHandler(stream_handler)
    
    return logger


def format_event_text(event: Event) -> str:
    """Return human-readable line for an event."""
    alert_prefix = "ALERT " if event.is_alert else ""
    # For move/rename events, the message already contains the full move information
    # For other events, show the path
    if event.event_type in ("rename", "move_internal", "move_in", "move_out"):
        # Extract the path information from message (e.g., "RENAME old -> new" -> "old -> new")
        path_display = event.message.replace(event.event_type.upper() + " ", "")
    else:
        path_display = event.path
    return (
        f"[{event.timestamp.isoformat()}] {alert_prefix}{event.event_type.upper()} {path_display} "
        f"(severity={event.severity}, risk={event.risk_score}, ai_risk={event.ai_risk_score})"
    )


def event_to_log_payload(event: Event, wazuh_format: bool = False) -> Dict[str, Any]:
    """Expose event dict publicly."""
    return _event_to_dict(event, wazuh_format=wazuh_format)


__all__ = ["setup_logging", "get_logger", "format_event_text", "event_to_log_payload"]

