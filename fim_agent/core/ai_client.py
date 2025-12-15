"""OpenAI client integration for AI-powered event analysis."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from fim_agent.core.events import Event
from fim_agent.core.logging_utils import get_logger

logger = get_logger(__name__)


def get_openai_client() -> Optional[Any]:
    """
    Get OpenAI client if API key is configured.
    
    Returns:
        OpenAI client instance if OPENAI_API_KEY is set, None otherwise.
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key or not api_key.strip():
        return None
    
    try:
        from openai import OpenAI
        return OpenAI(api_key=api_key)
    except ImportError:
        logger.warning("OpenAI package not installed. Install with: pip install openai")
        return None
    except Exception as e:
        logger.warning(f"Failed to initialize OpenAI client: {e}")
        return None


def _event_to_analysis_dict(event: Event) -> Dict[str, Any]:
    """
    Convert event to a compact dictionary for AI analysis.
    
    Includes only the most relevant fields for AI classification.
    """
    return {
        "event_type": event.event_type,
        "path": event.path,
        "old_path": event.old_path,
        "user": event.user,
        "user_type": event.user_type,
        "process_name": event.process_name,
        "risk_score": event.risk_score,
        "severity": event.severity,
        "content_classification": event.content_classification,
        "content_flags": event.content_flags or [],
        "mitre_tags": event.mitre_tags or [],
        "hash_changed": event.hash_changed,
        "is_alert": event.is_alert,
        "content_score": event.content_score,
    }


def analyze_event_with_ai(event: Event) -> Dict[str, Any]:
    """
    Analyze an event using OpenAI API.
    
    Args:
        event: The Event object to analyze
        
    Returns:
        Dictionary with keys: classification, ai_risk_score, reason, remediation
        Returns empty dict if OpenAI is not available or call fails.
    """
    client = get_openai_client()
    if not client:
        return {}
    
    try:
        # Build event data for prompt
        event_data = _event_to_analysis_dict(event)
        
        # Build prompt
        prompt = (
            "You are a SOC analyst for a file integrity monitoring system. "
            "Given the following event JSON, classify it and suggest remediation. "
            "Respond ONLY in JSON with the keys: classification, ai_risk_score, reason, remediation.\n\n"
            "Event:\n" + json.dumps(event_data, indent=2)
        )
        
        # Call OpenAI API
        # Note: Using chat.completions.create as it's the standard API
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Using gpt-4o-mini instead of gpt-4.1-mini (which doesn't exist)
            messages=[
                {
                    "role": "system",
                    "content": "You are a security analyst. Respond only with valid JSON, no additional text."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=500,
        )
        
        # Extract response text
        if not response.choices or not response.choices[0].message.content:
            logger.warning("OpenAI returned empty response")
            return {}
        
        text = response.choices[0].message.content.strip()
        
        # Try to extract JSON if response is wrapped in markdown code blocks
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        
        # Parse JSON
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse OpenAI response as JSON: {e}. Response: {text[:200]}")
            return {}
        
        # Normalize and validate payload
        result: Dict[str, Any] = {}
        
        # Classification (string)
        if "classification" in payload:
            classification = str(payload["classification"]).lower()
            if classification in ("public", "internal", "sensitive", "private", "secret"):
                result["classification"] = classification
        
        # AI risk score (0-100 int)
        if "ai_risk_score" in payload:
            try:
                score = int(payload["ai_risk_score"])
                result["ai_risk_score"] = max(0, min(100, score))  # Clamp to 0-100
            except (ValueError, TypeError):
                pass
        
        # Reason (string)
        if "reason" in payload:
            reason = str(payload["reason"]).strip()
            if reason:
                result["reason"] = reason
        
        # Remediation (string)
        if "remediation" in payload:
            remediation = str(payload["remediation"]).strip()
            if remediation:
                result["remediation"] = remediation
        
        return result
        
    except Exception as e:
        logger.warning(f"OpenAI API call failed: {e}", exc_info=True)
        return {}

