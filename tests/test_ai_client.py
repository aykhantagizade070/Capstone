"""Tests for OpenAI AI client integration."""

import json
import os
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

import pytest

from fim_agent.core.ai_client import get_openai_client, analyze_event_with_ai, _event_to_analysis_dict
from fim_agent.core.events import Event


def test_get_openai_client_no_key():
    """Test that get_openai_client returns None when OPENAI_API_KEY is not set."""
    with patch.dict(os.environ, {}, clear=True):
        client = get_openai_client()
        assert client is None


def test_get_openai_client_with_key():
    """Test that get_openai_client returns a client when OPENAI_API_KEY is set."""
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key-123"}):
        with patch("fim_agent.core.ai_client.OpenAI") as mock_openai:
            mock_client = Mock()
            mock_openai.return_value = mock_client
            client = get_openai_client()
            assert client is not None
            mock_openai.assert_called_once_with(api_key="test-key-123")


def test_get_openai_client_import_error():
    """Test that get_openai_client handles ImportError gracefully."""
    with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
        with patch("fim_agent.core.ai_client.OpenAI", side_effect=ImportError("No module named 'openai'")):
            client = get_openai_client()
            assert client is None


def test_event_to_analysis_dict():
    """Test that _event_to_analysis_dict creates a compact event representation."""
    event = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/etc/config.yaml",
        old_hash="abc",
        new_hash="def",
        severity="high",
        mitre_tags=["Tampering", "Config Manipulation"],
        message="MODIFY /etc/config.yaml",
        user="admin",
        user_type="human",
        process_name="editor.exe",
        risk_score=75,
        content_classification="private",
        content_flags=["suspicious_base64"],
        hash_changed=True,
        is_alert=True,
        content_score=20,
    )
    
    result = _event_to_analysis_dict(event)
    
    assert result["event_type"] == "modify"
    assert result["path"] == "/etc/config.yaml"
    assert result["user"] == "admin"
    assert result["risk_score"] == 75
    assert result["content_classification"] == "private"
    assert result["mitre_tags"] == ["Tampering", "Config Manipulation"]
    assert result["is_alert"] is True


def test_analyze_event_with_ai_no_client():
    """Test that analyze_event_with_ai returns empty dict when no client is available."""
    with patch("fim_agent.core.ai_client.get_openai_client", return_value=None):
        event = Event(
            timestamp=datetime.utcnow(),
            event_type="modify",
            path="/etc/config.yaml",
            old_hash="abc",
            new_hash="def",
            severity="high",
            mitre_tags=[],
            message="MODIFY",
        )
        result = analyze_event_with_ai(event)
        assert result == {}


def test_analyze_event_with_ai_success():
    """Test successful OpenAI API call and response parsing."""
    event = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/etc/config.yaml",
        old_hash="abc",
        new_hash="def",
        severity="high",
        mitre_tags=["Tampering"],
        message="MODIFY",
        risk_score=75,
        content_classification="private",
        is_alert=True,
    )
    
    # Mock OpenAI response
    mock_response = Mock()
    mock_choice = Mock()
    mock_message = Mock()
    mock_message.content = json.dumps({
        "classification": "sensitive",
        "ai_risk_score": 85,
        "reason": "High-risk configuration file modification with private content",
        "remediation": "Review file changes immediately. Verify authorization and check for unauthorized access."
    })
    mock_choice.message = mock_message
    mock_response.choices = [mock_choice]
    
    mock_client = Mock()
    mock_client.chat.completions.create.return_value = mock_response
    
    with patch("fim_agent.core.ai_client.get_openai_client", return_value=mock_client):
        result = analyze_event_with_ai(event)
        
        assert result["classification"] == "sensitive"
        assert result["ai_risk_score"] == 85
        assert "reason" in result
        assert "remediation" in result
        mock_client.chat.completions.create.assert_called_once()


def test_analyze_event_with_ai_json_in_code_block():
    """Test that analyze_event_with_ai handles JSON wrapped in markdown code blocks."""
    event = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/etc/config.yaml",
        old_hash="abc",
        new_hash="def",
        severity="high",
        mitre_tags=[],
        message="MODIFY",
    )
    
    # Mock OpenAI response with JSON in code block
    mock_response = Mock()
    mock_choice = Mock()
    mock_message = Mock()
    mock_message.content = "```json\n" + json.dumps({
        "classification": "internal",
        "ai_risk_score": 60,
        "reason": "Test reason",
        "remediation": "Test remediation"
    }) + "\n```"
    mock_choice.message = mock_message
    mock_response.choices = [mock_choice]
    
    mock_client = Mock()
    mock_client.chat.completions.create.return_value = mock_response
    
    with patch("fim_agent.core.ai_client.get_openai_client", return_value=mock_client):
        result = analyze_event_with_ai(event)
        
        assert result["classification"] == "internal"
        assert result["ai_risk_score"] == 60


def test_analyze_event_with_ai_invalid_json():
    """Test that analyze_event_with_ai handles invalid JSON gracefully."""
    event = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/etc/config.yaml",
        old_hash="abc",
        new_hash="def",
        severity="high",
        mitre_tags=[],
        message="MODIFY",
    )
    
    # Mock OpenAI response with invalid JSON
    mock_response = Mock()
    mock_choice = Mock()
    mock_message = Mock()
    mock_message.content = "This is not valid JSON"
    mock_choice.message = mock_message
    mock_response.choices = [mock_choice]
    
    mock_client = Mock()
    mock_client.chat.completions.create.return_value = mock_response
    
    with patch("fim_agent.core.ai_client.get_openai_client", return_value=mock_client):
        result = analyze_event_with_ai(event)
        assert result == {}


def test_analyze_event_with_ai_api_exception():
    """Test that analyze_event_with_ai handles API exceptions gracefully."""
    event = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/etc/config.yaml",
        old_hash="abc",
        new_hash="def",
        severity="high",
        mitre_tags=[],
        message="MODIFY",
    )
    
    mock_client = Mock()
    mock_client.chat.completions.create.side_effect = Exception("API Error")
    
    with patch("fim_agent.core.ai_client.get_openai_client", return_value=mock_client):
        result = analyze_event_with_ai(event)
        assert result == {}


def test_analyze_event_with_ai_score_clamping():
    """Test that ai_risk_score is clamped to 0-100 range."""
    event = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/etc/config.yaml",
        old_hash="abc",
        new_hash="def",
        severity="high",
        mitre_tags=[],
        message="MODIFY",
    )
    
    # Test score > 100
    mock_response = Mock()
    mock_choice = Mock()
    mock_message = Mock()
    mock_message.content = json.dumps({
        "classification": "sensitive",
        "ai_risk_score": 150,  # Should be clamped to 100
        "reason": "Test",
        "remediation": "Test"
    })
    mock_choice.message = mock_message
    mock_response.choices = [mock_choice]
    
    mock_client = Mock()
    mock_client.chat.completions.create.return_value = mock_response
    
    with patch("fim_agent.core.ai_client.get_openai_client", return_value=mock_client):
        result = analyze_event_with_ai(event)
        assert result["ai_risk_score"] == 100
    
    # Test score < 0
    mock_message.content = json.dumps({
        "classification": "sensitive",
        "ai_risk_score": -10,  # Should be clamped to 0
        "reason": "Test",
        "remediation": "Test"
    })
    
    with patch("fim_agent.core.ai_client.get_openai_client", return_value=mock_client):
        result = analyze_event_with_ai(event)
        assert result["ai_risk_score"] == 0


def test_analyze_event_with_ai_invalid_classification():
    """Test that invalid classification values are ignored."""
    event = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/etc/config.yaml",
        old_hash="abc",
        new_hash="def",
        severity="high",
        mitre_tags=[],
        message="MODIFY",
    )
    
    mock_response = Mock()
    mock_choice = Mock()
    mock_message = Mock()
    mock_message.content = json.dumps({
        "classification": "invalid_classification",  # Should be ignored
        "ai_risk_score": 75,
        "reason": "Test",
        "remediation": "Test"
    })
    mock_choice.message = mock_message
    mock_response.choices = [mock_choice]
    
    mock_client = Mock()
    mock_client.chat.completions.create.return_value = mock_response
    
    with patch("fim_agent.core.ai_client.get_openai_client", return_value=mock_client):
        result = analyze_event_with_ai(event)
        assert "classification" not in result  # Invalid classification should be ignored
        assert result["ai_risk_score"] == 75


def test_watcher_ai_integration(tmp_path):
    """Test that watcher integrates AI client correctly for interesting events."""
    from fim_agent.core.watcher import _should_analyze_with_ai
    from fim_agent.core.events import Event
    
    # Test event with alert=True
    alert_event = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/etc/config.yaml",
        old_hash="abc",
        new_hash="def",
        severity="high",
        mitre_tags=[],
        message="MODIFY",
        is_alert=True,
    )
    assert _should_analyze_with_ai(alert_event) is True
    
    # Test event with risk_score >= 60
    high_risk_event = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/etc/config.yaml",
        old_hash="abc",
        new_hash="def",
        severity="high",
        mitre_tags=[],
        message="MODIFY",
        risk_score=65,
    )
    assert _should_analyze_with_ai(high_risk_event) is True
    
    # Test event with private content
    private_event = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/data/private.txt",
        old_hash="abc",
        new_hash="def",
        severity="medium",
        mitre_tags=[],
        message="MODIFY",
        content_classification="private",
    )
    assert _should_analyze_with_ai(private_event) is True
    
    # Test event with secret content
    secret_event = Event(
        timestamp=datetime.utcnow(),
        event_type="modify",
        path="/data/secret.txt",
        old_hash="abc",
        new_hash="def",
        severity="medium",
        mitre_tags=[],
        message="MODIFY",
        content_classification="secret",
    )
    assert _should_analyze_with_ai(secret_event) is True
    
    # Test event that doesn't meet criteria
    normal_event = Event(
        timestamp=datetime.utcnow(),
        event_type="create",
        path="/tmp/file.txt",
        old_hash=None,
        new_hash="abc",
        severity="low",
        mitre_tags=[],
        message="CREATE",
        risk_score=30,
        content_classification="public",
        is_alert=False,
    )
    assert _should_analyze_with_ai(normal_event) is False

