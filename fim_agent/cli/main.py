"""Main CLI entry point for the FIM agent."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
import logging
from pathlib import Path
from datetime import datetime

from fim_agent.core.config import Config, load_config
from fim_agent.core.hasher import build_baseline
from fim_agent.core.storage import Storage
from fim_agent.core.watcher import run_watcher
from fim_agent.core.logging_utils import setup_logging, format_event_text, event_to_log_payload
from fim_agent.web.api import create_app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FIM Agent CLI")
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to configuration file (defaults to config/config.yaml or config/config_example.yaml)",
    )

    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("init-baseline", help="Build baseline for monitored directories")
    subparsers.add_parser("run-agent", help="Start real-time watcher")
    timeline_parser = subparsers.add_parser("timeline", help="Show chronological event timeline")
    timeline_parser.add_argument("--severity", type=str, choices=["low", "medium", "high"], default=None)
    timeline_parser.add_argument("--path-filter", type=str, default=None, help="Filter events containing this path fragment")
    timeline_parser.add_argument("--from", dest="from_ts", type=str, default=None, help="Start timestamp (ISO 8601)")
    timeline_parser.add_argument("--to", dest="to_ts", type=str, default=None, help="End timestamp (ISO 8601)")
    serve_web_parser = subparsers.add_parser("serve-web", help="Start web API server")
    serve_web_parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    serve_web_parser.add_argument("--port", type=int, default=8000, help="Port to bind to (default: 8000)")
    return parser.parse_args()


def _check_admin_password_env(config: Config) -> bool:
    """
    Check if admin password is set in environment variable (non-interactive).
    Returns True if password is configured, False otherwise.
    Does NOT prompt for password - admin approval is handled via web UI only.
    """
    expected_password = os.getenv(config.admin_password_env_var) or os.getenv("FIM_DASHBOARD_PASSWORD")
    if not expected_password:
        return False
    return True


def _configure_logging(config: Config) -> None:
    """Configure file logging if a log file is specified."""
    log_path = Path(config.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(log_path, encoding="utf-8")],
    )


def main() -> int:
    """Main entry point for the FIM agent CLI."""
    args = parse_args()
    try:
        config: Config = load_config(args.config)
    except FileNotFoundError as exc:
        print(f"Error: {exc}")
        return 1

    if args.command == "init-baseline":
        storage = Storage(config.database_path)
        storage.init_schema()
        directories = [Path(p) for p in config.monitored_directories]
        hashed = build_baseline(directories, storage, config)
        print(f"Baseline initialized. Files hashed: {hashed}")
        return 0

    if args.command == "run-agent":
        storage = Storage(config.database_path)
        storage.init_schema()

        logger = setup_logging(config)

        def print_event(event):
            # Check if event requires admin approval
            if event.requires_admin_approval and not event.admin_approved:
                print(f"\n⚠️  ADMIN APPROVAL REQUIRED ⚠️")
                print(f"Event: {event.message}")
                print(f"Risk Score: {event.risk_score}, AI Risk Score: {event.ai_risk_score}")
                print(f"File: {event.path}")
                if event.content_classification in ("private", "secret"):
                    print(f"⚠️  SENSITIVE CONTENT: {event.content_classification.upper()}")
                    if event.classification_matches:
                        print(f"   Matched keywords: {', '.join(event.classification_matches[:3])}")
                if event.hash_changed:
                    print(f"⚠️  WARNING: File hash changed! Integrity violation detected.")
                
                # Admin approval is handled via web UI only - no CLI password prompt
                has_password_env = _check_admin_password_env(config)
                if has_password_env:
                    print("⚠️  Admin approval required. Use the web UI to approve this event.")
                else:
                    print(f"⚠️  Admin approval required. Set {config.admin_password_env_var} or FIM_DASHBOARD_PASSWORD to enable web UI approval.")
                # Event remains pending approval (admin_approved = False) until approved via web UI
                event.admin_approved = False
            
            # Log the event
            if config.log_format == "json":
                logger.info(event_to_log_payload(event))
            else:
                line = format_event_text(event)
                logger.info(line)
                if event.requires_admin_approval:
                    approval_status = "APPROVED" if event.admin_approved else "PENDING"
                    logger.info(f"  [Admin Approval: {approval_status}]")

        if storage.count_files() == 0:
            print("Warning: baseline appears empty; consider running init-baseline first.")

        print("Starting watcher. Press Ctrl+C to stop.")
        if config.require_admin_for_alerts:
            print(f"Admin approval enabled. Password from: {config.admin_password_env_var}")
        run_watcher(config, storage, print_event)
        return 0

    if args.command == "timeline":
        storage = Storage(config.database_path)
        storage.init_schema()

        def parse_iso(ts: str | None) -> datetime | None:
            return datetime.fromisoformat(ts) if ts else None

        events = storage.get_events(
            from_ts=parse_iso(args.from_ts),
            to_ts=parse_iso(args.to_ts),
            path_filter=args.path_filter,
            severity=args.severity,
        )
        
        if not events:
            print("No events found in database.")
            print(f"Database path: {config.database_path}")
            # Debug: check if table exists and has rows
            cursor = storage.conn.execute("SELECT COUNT(*) as c FROM events")
            row = cursor.fetchone()
            total_count = int(row["c"]) if row else 0
            if total_count > 0:
                print(f"Total events in database: {total_count}")
                print("Note: Events may be filtered out by your query parameters.")
            return 0
        
        print("timestamp | event_type | severity | path | risk_score | ai_risk_score | alert | approval | message")
        for ev in events:
            alert_marker = "!" if ev.is_alert else "-"
            if ev.requires_admin_approval:
                approval_status = "APPROVED" if ev.admin_approved else "PENDING"
            else:
                approval_status = "-"
            print(
                f"{ev.timestamp.isoformat()} | {ev.event_type} | {ev.severity} | "
                f"{ev.path} | {ev.risk_score} | {ev.ai_risk_score} | {alert_marker} | {approval_status} | {ev.message}"
            )
        return 0

    if args.command == "serve-web":
        try:
            import uvicorn
        except ImportError:
            print("Error: uvicorn is required for serve-web. Install it with: pip install uvicorn")
            return 1
        
        app = create_app(config)
        host = args.host
        port = args.port
        
        print(f"Starting FIM Agent web API server on http://{host}:{port}")
        print(f"API documentation available at http://{host}:{port}/docs")
        print(f"API root: http://{host}:{port}/api/events")
        print("Press Ctrl+C to stop.")
        
        uvicorn.run(app, host=host, port=port)
        return 0

    print("FIM Agent - File Integrity Monitoring System")
    print("Loaded configuration:")
    print(json.dumps(asdict(config), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

