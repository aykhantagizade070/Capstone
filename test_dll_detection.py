#!/usr/bin/env python3
"""
Test script for DLL Detection feature in FIM Agent.

This script demonstrates the DLL detection capability that classifies
suspicious .dll drops as Execution/Defense Evasion with high risk.

Features tested:
- DLL file creation detection
- Automatic classification as high-risk executable drop
- MITRE ATT&CK tags: Execution, Defense Evasion
- Content flags: ["extension:dll", "executable_drop"]
- Risk score >= 80
"""

import os
import sys
import time
import tempfile
import subprocess
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from fim_agent.core.config import load_config
from fim_agent.core.storage import Storage
from fim_agent.core.events import Event, simple_risk_score
from datetime import datetime


def create_test_dll(watched_dir: Path) -> Path:
    """Create a dummy DLL file in the watched directory."""
    dll_path = watched_dir / "test_malicious.dll"

    # Create a simple DLL-like content (this is just for testing)
    dll_content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"

    with open(dll_path, 'wb') as f:
        f.write(dll_content)

    print(f"Created test DLL: {dll_path}")
    return dll_path


def simulate_dll_detection(dll_path: Path):
    """Simulate the DLL detection logic."""
    print("\n=== Simulating DLL Detection ===")

    # Create an event as the FIM agent would
    event = Event(
        timestamp=datetime.utcnow(),
        event_type="create",
        path=str(dll_path),
        old_hash=None,
        new_hash="dummy_hash_12345",  # In real scenario, this would be computed
        severity="low",
        mitre_tags=[],
        message=f"CREATE {dll_path}",
        content_flags=["extension:dll"],  # This would be set by content inspector
        content_score=15,  # Extension score
    )

    print(f"Event created: {event.message}")
    print(f"Initial content_flags: {event.content_flags}")

    # Apply risk scoring (this triggers the executable_drop logic)
    risk_score = simple_risk_score(event)

    print("After risk assessment:\n")
    print(f"Risk score: {risk_score}")
    print(f"Content flags: {event.content_flags}")
    print(f"MITRE tags: {event.mitre_tags}")

    # Verify the expected behavior
    assert risk_score >= 80, f"Expected risk_score >= 80, got {risk_score}"
    assert "executable_drop" in event.content_flags, "Expected 'executable_drop' in content_flags"
    assert "extension:dll" in event.content_flags, "Expected 'extension:dll' in content_flags"
    assert "Execution" in event.mitre_tags, "Expected 'Execution' in MITRE tags"
    assert "Defense Evasion" in event.mitre_tags, "Expected 'Defense Evasion' in MITRE tags"

    print("\n✅ All assertions passed! DLL detection working correctly.")


def run_full_agent_test(config_path: str):
    """Run a full test with the actual FIM agent."""
    print("\n=== Running Full Agent Test ===")

    config = load_config(config_path)
    watched_dir = Path(config.monitored_directories[0]).resolve()

    print(f"Watched directory: {watched_dir}")

    # Ensure watched directory exists
    watched_dir.mkdir(exist_ok=True)

    # Clean up any existing test files
    test_dll = watched_dir / "test_malicious.dll"
    if test_dll.exists():
        test_dll.unlink()
        print(f"Cleaned up existing test file: {test_dll}")

    # Initialize storage
    storage = Storage(config.database_path)

    # Build baseline (this should not include our test DLL yet)
    print("Building baseline...")
    from fim_agent.core.hasher import build_baseline
    baseline = build_baseline(config.monitored_directories, storage, config)
    print("Baseline built and saved.")

    # Create the test DLL
    dll_path = create_test_dll(watched_dir)

    # Simulate the watcher detecting the file (in a real scenario, the watcher would do this)
    print("Simulating file creation detection...")

    # Calculate hash for the new file
    from fim_agent.core.hasher import compute_file_hash
    new_hash = compute_file_hash(dll_path)

    # Create event
    event = Event(
        timestamp=datetime.utcnow(),
        event_type="create",
        path=str(dll_path),
        old_hash=None,
        new_hash=new_hash,
        severity="low",
        mitre_tags=[],
        message=f"CREATE {dll_path}",
    )

    # Apply content analysis
    from fim_agent.core.content_inspector import analyze_file_content
    content_analysis = analyze_file_content(dll_path, event)
    event.content_flags = content_analysis.flags
    event.content_score = content_analysis.score
    event.content_classification = content_analysis.classification
    event.classification_matches = content_analysis.classification_matches

    # Apply risk scoring
    risk_score = simple_risk_score(event)
    event.risk_score = risk_score

    # Save the event
    storage.record_event(event)

    print("Event details:\n")
    print(f"Path: {event.path}")
    print(f"Event type: {event.event_type}")
    print(f"Risk score: {event.risk_score}")
    print(f"Content flags: {event.content_flags}")
    print(f"MITRE tags: {event.mitre_tags}")
    print(f"Content classification: {event.content_classification}")

    # Verify expectations
    assert event.risk_score >= 80, f"Risk score should be >= 80, got {event.risk_score}"
    assert "extension:.dll" in event.content_flags, "Should have extension:.dll flag"
    assert "executable_drop" in event.content_flags, "Should have executable_drop flag"
    assert "Execution" in event.mitre_tags, "Should have Execution tag"
    assert "Defense Evasion" in event.mitre_tags, "Should have Defense Evasion tag"

    print("\n✅ Full agent test passed!")

    # Show timeline
    print("\n=== Event Timeline ===")
    events = storage.get_events(limit=10)
    for ev in events:
        print(f"{ev.timestamp} | {ev.event_type} | {ev.severity} | {ev.path} | {ev.risk_score} | {ev.ai_risk_score} | {ev.message}")

    # Clean up
    dll_path.unlink()
    print(f"\nCleaned up test file: {dll_path}")


def main():
    """Main test function."""
    print("FIM Agent - DLL Detection Test Script")
    print("=" * 50)

    # Check if config exists
    config_path = project_root / "config" / "config.yaml"
    if not config_path.exists():
        config_path = project_root / "config" / "config_example.yaml"
        if not config_path.exists():
            print("❌ Config file not found. Please ensure config/config.yaml or config/config_example.yaml exists.")
            return 1

    print(f"Using config: {config_path}")

    # Run simulation test
    simulate_dll_detection(Path("dummy.dll"))

    # Run full agent test
    try:
        run_full_agent_test(str(config_path))
    except Exception as e:
        print(f"❌ Full agent test failed: {e}")
        return 1

    print("\n🎉 All tests passed! DLL detection feature is working correctly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())