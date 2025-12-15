"""
File system watcher for real-time monitoring.

MODIFICATIONS FOR NON-INTERACTIVE ADMIN APPROVAL:
- All admin approval is handled via the web UI only. No CLI password prompts.
- When events require admin approval (requires_admin_approval=True), the watcher:
  * Logs a warning message with event details
  * Sets event.requires_admin_approval = True
  * Sets event.admin_approved = False
  * Continues processing immediately without blocking
- Modified functions:
  * _process_move(): Added non-interactive logging for admin approval (lines ~384-390)
  * _process(): Added non-interactive logging for admin approval (lines ~519-525)
- No calls to input(), getpass.getpass(), or any stdin-based password prompts exist.
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable, Optional, Tuple

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from fim_agent.core.config import Config
from fim_agent.core.events import (
    Event,
    calculate_severity,
    map_mitre_tags,
    infer_user,
    infer_user_type,
    simple_risk_score,
    simple_ai_classification,
    mark_alert,
)
from fim_agent.core.governance import TAMPER_EVENTS, mark_requires_admin_approval, SENSITIVE_PATHS, _norm_path
from fim_agent.core.hasher import compute_file_hash
from fim_agent.core.storage import Storage
from fim_agent.core.content_inspector import analyze_file_content
from fim_agent.core.ai_client import analyze_event_with_ai
from fim_agent.core.logging_utils import get_logger

logger = get_logger(__name__)


def _should_analyze_with_ai(event: Event) -> bool:
    """
    Determine if an event is "interesting" enough to call OpenAI API.
    
    Only call OpenAI for events that meet certain criteria to control costs:
    - event.is_alert is True, OR
    - risk_score >= 60, OR
    - content_classification in {"private", "secret"}
    
    Args:
        event: The event to check
        
    Returns:
        True if event should be analyzed with AI, False otherwise
    """
    if event.is_alert:
        return True
    if event.risk_score is not None and event.risk_score >= 60:
        return True
    if event.content_classification in ("private", "secret"):
        return True
    return False


HandlerCallback = Callable[[Event], None]


def _is_in_monitored(path: Path, config: Config) -> bool:
    """Check if a path is inside any monitored directory."""
    resolved = path.resolve()
    monitored_dirs = [Path(p).resolve() for p in config.monitored_directories]
    for mon_dir in monitored_dirs:
        try:
            resolved.relative_to(mon_dir)
            return True
        except ValueError:
            continue
    return False


def _classify_move(src: Path, dest: Path, config: Config) -> Optional[str]:
    """
    Classify a move operation based on source and destination locations.
    
    Returns:
        "rename" if same directory, different filename (both in monitored)
        "move_internal" if different directory within monitored tree
        "move_in" if from outside into monitored
        "move_out" if from monitored to outside
        None if both outside monitored or invalid
    """
    src_resolved = src.resolve()
    dest_resolved = dest.resolve()
    
    src_in = _is_in_monitored(src_resolved, config)
    dest_in = _is_in_monitored(dest_resolved, config)
    
    if src_in and dest_in:
        # Both in monitored: check if same directory (rename) or different (move_internal)
        if src_resolved.parent == dest_resolved.parent:
            return "rename"
        else:
            return "move_internal"
    elif not src_in and dest_in:
        # Moving into monitored area
        return "move_in"
    elif src_in and not dest_in:
        # Moving out of monitored area
        return "move_out"
    else:
        # Both outside monitored
        return None


def _is_excluded(path: Path, config: Config) -> bool:
    """Check if path should be excluded based on directories or extensions."""
    resolved = path.resolve()
    exclude_dirs = [Path(p).resolve() for p in config.exclude_directories]
    for ex_dir in exclude_dirs:
        try:
            resolved.relative_to(ex_dir)
            return True
        except ValueError:
            continue
    if resolved.suffix in set(config.exclude_extensions):
        return True
    return False


class WatchHandler(FileSystemEventHandler):
    """Watchdog handler that produces Event objects and writes to storage."""

    def __init__(self, config: Config, storage: Storage, callback: HandlerCallback):
        super().__init__()
        self.config = config
        self.storage = storage
        self.callback = callback
        # Correlation buffer for DELETE+CREATE pairs that represent moves
        # Key: (filename, hash), Value: (path, timestamp)
        self.recent_deletes: dict[Tuple[str, Optional[str]], Tuple[Path, datetime]] = {}
        self.correlation_window = timedelta(seconds=2)  # 2 second window for correlation

    def on_created(self, event):  # type: ignore[override]
        """Handle file creation, checking if it's part of a move operation."""
        if event.is_directory:
            return
        
        dest_path = Path(event.src_path).resolve()
        
        # Check if this CREATE might be part of a move (correlate with recent DELETE)
        if self._try_correlate_move(dest_path):
            return  # Move event was emitted, skip CREATE
        
        # Not a move, process as normal CREATE
        self._process(event, "create")

    def on_modified(self, event):  # type: ignore[override]
        self._process(event, "modify")

    def on_deleted(self, event):  # type: ignore[override]
        """Handle file deletion, storing info for potential move correlation."""
        if event.is_directory:
            return
        
        src_path = Path(event.src_path).resolve()
        
        # Check if excluded
        if _is_excluded(src_path, self.config):
            return
        
        # Get hash before deletion for correlation
        old_record = self.storage.get_file(str(src_path))
        old_hash = old_record["hash"] if old_record else None
        
        # Store delete info for potential correlation
        filename = src_path.name
        key = (filename, old_hash)
        self.recent_deletes[key] = (src_path, datetime.utcnow())
        
        # Clean up old entries
        now = datetime.utcnow()
        self.recent_deletes = {
            k: v for k, v in self.recent_deletes.items()
            if now - v[1] < self.correlation_window
        }
        
        # Process as DELETE (will be suppressed later if move is detected via CREATE)
        # Note: We can't suppress it here because we don't know yet if a CREATE will follow
        # The CREATE handler will suppress its own event if it correlates with this DELETE
        self._process(event, "delete")
    
    def _try_correlate_move(self, dest_path: Path) -> bool:
        """
        Check if dest_path matches a recent DELETE, indicating a move operation.
        Returns True if a move event was emitted, False otherwise.
        """
        if _is_excluded(dest_path, self.config):
            return False
        
        # Try to compute hash of new file
        try:
            new_hash = compute_file_hash(dest_path)
        except (OSError, PermissionError):
            return False
        
        filename = dest_path.name
        now = datetime.utcnow()
        
        # Look for matching DELETE by filename and hash
        matched_key = None
        matched_info = None
        
        for key, (src_path, delete_time) in list(self.recent_deletes.items()):
            if now - delete_time > self.correlation_window:
                continue  # Too old
            
            stored_filename, stored_hash = key
            if stored_filename == filename:
                # Filename matches, check hash if available
                if stored_hash is None or stored_hash == new_hash:
                    matched_key = key
                    matched_info = (src_path, delete_time)
                    break
        
        if matched_key is None:
            return False  # No matching DELETE found
        
        # Found a match - this is a move operation
        src_path, delete_time = matched_info
        del self.recent_deletes[matched_key]
        
        # Classify the move
        event_type = _classify_move(src_path, dest_path, self.config)
        if event_type is None:
            return False  # Not a monitored move
        
        # Remove the DELETE event that was already stored (it's part of this move)
        self.storage.remove_recent_delete_event(str(src_path), within_seconds=2.0)
        
        # Process as move event
        self._process_move(src_path, dest_path, event_type)
        return True
    
    def _process_move(self, src: Path, dest: Path, event_type: str) -> None:
        """Process a move operation and emit the appropriate Event."""
        timestamp = datetime.utcnow()
        
        # Get the old record to preserve hash (only if src was in monitored)
        src_in = _is_in_monitored(src, self.config)
        dest_in = _is_in_monitored(dest, self.config)
        
        old_record = None
        old_hash = None
        if src_in:
            old_record = self.storage.get_file(str(src))
            old_hash = old_record["hash"] if old_record else None
        
        # Compute hash for new path (only if dest is in monitored)
        new_hash = None
        if dest_in:
            try:
                new_hash = compute_file_hash(dest)
            except (OSError, PermissionError):
                return
        
        # Use dest path for event (or src if dest not in monitored)
        event_path = str(dest) if dest_in else str(src)
        event_path_resolved = Path(event_path).resolve()
        src_path_resolved = src.resolve()
        
        # Check if this path has been seen before (BEFORE updating baseline)
        # For move events, check the destination path (or source if dest not monitored)
        first_seen = not self.storage.has_seen_path(event_path)
        
        # Update baseline based on event type
        if event_type == "move_out":
            # File leaving monitored area - mark as deleted in baseline
            if old_record:
                self.storage.upsert_file(str(src), old_hash or "", "delete", timestamp)
        elif event_type == "move_in":
            # File entering monitored area - treat as new file
            if new_hash:
                self.storage.upsert_file(str(dest), new_hash, "create", timestamp)
        elif event_type in ("rename", "move_internal"):
            # Update baseline: move old_path record to new_path
            if old_record:
                self.storage.update_file_path(str(src), str(dest))
            elif new_hash:
                # If no old record, treat as new file
                self.storage.upsert_file(str(dest), new_hash, event_type, timestamp)
        
        # Use dest path for severity calculation (or src if dest not in monitored)
        path_for_severity = str(dest) if dest_in else str(src)
        severity = calculate_severity(path_for_severity)
        mitre_tags = map_mitre_tags(path_for_severity, event_type)
        user = infer_user()
        user_type = infer_user_type(user)
        process_name = Path(os.sys.argv[0]).name if os.sys.argv else None
        hash_changed = None
        if new_hash is not None and old_hash is not None:
            hash_changed = new_hash != old_hash
        
        # Format message based on event type
        if event_type == "rename":
            message = f"RENAME {src} -> {dest}"
        elif event_type == "move_internal":
            message = f"MOVE_INTERNAL {src} -> {dest}"
        elif event_type == "move_in":
            message = f"MOVE_IN {src} -> {dest}"
        else:  # move_out
            message = f"MOVE_OUT {src} -> {dest}"
        
        event_obj = Event(
            timestamp=timestamp,
            event_type=event_type,  # type: ignore[arg-type]
            path=event_path,
            old_hash=old_hash,
            new_hash=new_hash,
            severity=severity,
            mitre_tags=mitre_tags,
            message=message,
            user=user,
            user_type=user_type,
            process_name=process_name,
            sha256=new_hash,
            previous_sha256=old_hash,
            hash_changed=hash_changed,
            old_path=str(src),
            first_seen=first_seen,
        )
        # Content inspection for move_in events (file entering monitored area)
        if event_type == "move_in" and dest_in:
            try:
                analysis = analyze_file_content(dest, event_obj)
                event_obj.content_score = analysis.score
                event_obj.content_flags = analysis.flags or []
                event_obj.content_classification = analysis.classification
                event_obj.classification_matches = analysis.classification_matches or []
            except Exception:
                # On any error, continue without content inspection
                pass
        # Enrich with risk scoring and AI-like classification
        event_obj.risk_score = simple_risk_score(event_obj)
        
        # Update severity based on risk_score (override initial severity calculation)
        from fim_agent.core.events import derive_severity_from_risk
        event_obj.severity = derive_severity_from_risk(event_obj.risk_score)
        
        # Run rule-based AI classification first (fallback)
        ai_class, ai_risk, ai_reason = simple_ai_classification(event_obj)
        event_obj.ai_classification = ai_class
        event_obj.ai_risk_score = ai_risk
        event_obj.ai_risk_reason = ai_reason
        
        # Generate rule-based AI recommendation (fallback)
        from fim_agent.core.governance import generate_ai_recommendation
        event_obj.ai_recommendation = generate_ai_recommendation(event_obj)
        
        # Mark as alert if thresholds are met (includes forced alerts for tamper events on sensitive files)
        mark_alert(event_obj, self.config.alert_min_risk_score, self.config.alert_min_ai_risk_score)
        
        # Optionally enhance with real OpenAI AI analysis for "interesting" events
        if _should_analyze_with_ai(event_obj):
            ai_result = analyze_event_with_ai(event_obj)
            if ai_result:
                # Override/augment fields only if OpenAI returned valid data
                if "classification" in ai_result:
                    event_obj.ai_classification = ai_result["classification"]
                if "ai_risk_score" in ai_result:
                    event_obj.ai_risk_score = ai_result["ai_risk_score"]
                if "reason" in ai_result:
                    event_obj.ai_risk_reason = ai_result["reason"]
                if "remediation" in ai_result:
                    event_obj.ai_recommendation = ai_result["remediation"]
        
        # For rename/move events, update SENSITIVE_PATHS if old path was sensitive
        if event_obj.event_type in ("rename", "move_internal", "move_in", "move_out") and event_obj.old_path:
            old_path = _norm_path(event_obj.old_path)
            if old_path in SENSITIVE_PATHS:
                # Remove old path from set (file has moved)
                SENSITIVE_PATHS.discard(old_path)
                # Add new path to set (file is still sensitive at new location)
                new_path = _norm_path(event_obj.path)
                SENSITIVE_PATHS.add(new_path)
        
        # For move_in and TAMPER_EVENTS, call mark_requires_admin_approval
        if event_obj.event_type == "move_in" or event_obj.event_type in TAMPER_EVENTS:
            mark_requires_admin_approval(event_obj, self.config)
        
        # Log warning if admin approval is required (non-interactive - web UI handles approval)
        if event_obj.requires_admin_approval:
            logger.warning("ADMIN APPROVAL REQUIRED for event %s (path=%s, risk_score=%s)", 
                          event_obj.event_type, 
                          getattr(event_obj, "path", None),
                          getattr(event_obj, "risk_score", None))
            # Ensure flags are set correctly - web UI will handle actual approval
            event_obj.requires_admin_approval = True
            event_obj.admin_approved = False
        
        # Persist event before notifying callback
        self.storage.record_event(event_obj)
        self.callback(event_obj)

    def on_moved(self, event):  # type: ignore[override]
        """Handle file rename/move events (when watchdog emits MOVED event)."""
        if event.is_directory:
            return
        
        src = Path(event.src_path).resolve()
        dest = Path(event.dest_path).resolve()
        
        # Check if paths should be excluded
        if _is_excluded(src, self.config) or _is_excluded(dest, self.config):
            return
        
        # Classify the move
        event_type = _classify_move(src, dest, self.config)
        if event_type is None:
            return  # Not a monitored move
        
        # Process as move event
        self._process_move(src, dest, event_type)

    def _process(self, raw_event, event_type: str) -> None:
        """Process a standard file system event (create/modify/delete)."""
        if raw_event.is_directory:
            return

        path = Path(raw_event.src_path)
        if _is_excluded(path, self.config):
            return

        timestamp = datetime.utcnow()
        old_record = self.storage.get_file(str(path))
        old_hash = old_record["hash"] if old_record else None
        new_hash = None
        
        # Check if this path has been seen before (BEFORE updating baseline)
        first_seen = not self.storage.has_seen_path(str(path))

        if event_type in ("create", "modify"):
            try:
                new_hash = compute_file_hash(path)
            except (OSError, PermissionError):
                return
            self.storage.upsert_file(str(path), new_hash, event_type, timestamp)
        else:  # delete
            # Keep last known hash; mark event type
            self.storage.upsert_file(str(path), old_hash or "", event_type, timestamp)

        severity = calculate_severity(str(path))
        mitre_tags = map_mitre_tags(str(path), event_type)
        user = infer_user()
        user_type = infer_user_type(user)
        process_name = Path(os.sys.argv[0]).name if os.sys.argv else None
        hash_changed = None
        if new_hash is not None and old_hash is not None:
            hash_changed = new_hash != old_hash

        message = f"{event_type.upper()} {path}"
        
        event = Event(
            timestamp=timestamp,
            event_type=event_type,  # type: ignore[arg-type]
            path=str(path),
            old_hash=old_hash,
            new_hash=new_hash,
            severity=severity,
            mitre_tags=mitre_tags,
            message=message,
            user=user,
            user_type=user_type,
            process_name=process_name,
            sha256=new_hash,
            previous_sha256=old_hash,
            hash_changed=hash_changed,
            first_seen=first_seen,
        )
        # Content inspection for create/modify events
        if event_type in ("create", "modify"):
            try:
                analysis = analyze_file_content(path, event)
                event.content_score = analysis.score
                event.content_flags = analysis.flags or []
                event.content_classification = analysis.classification
                event.classification_matches = analysis.classification_matches or []
            except Exception:
                # On any error, continue without content inspection
                pass
        # Enrich with risk scoring and AI-like classification
        event.risk_score = simple_risk_score(event)
        
        # Update severity based on risk_score (override initial severity calculation)
        from fim_agent.core.events import derive_severity_from_risk
        event.severity = derive_severity_from_risk(event.risk_score)
        
        # Run rule-based AI classification first (fallback)
        ai_class, ai_risk, ai_reason = simple_ai_classification(event)
        event.ai_classification = ai_class
        event.ai_risk_score = ai_risk
        event.ai_risk_reason = ai_reason
        
        # Generate rule-based AI recommendation (fallback)
        from fim_agent.core.governance import generate_ai_recommendation
        event.ai_recommendation = generate_ai_recommendation(event)
        
        # Mark as alert if thresholds are met (includes forced alerts for tamper events on sensitive files)
        mark_alert(event, self.config.alert_min_risk_score, self.config.alert_min_ai_risk_score)
        
        # Optionally enhance with real OpenAI AI analysis for "interesting" events
        if _should_analyze_with_ai(event):
            ai_result = analyze_event_with_ai(event)
            if ai_result:
                # Override/augment fields only if OpenAI returned valid data
                if "classification" in ai_result:
                    event.ai_classification = ai_result["classification"]
                if "ai_risk_score" in ai_result:
                    event.ai_risk_score = ai_result["ai_risk_score"]
                if "reason" in ai_result:
                    event.ai_risk_reason = ai_result["reason"]
                if "remediation" in ai_result:
                    event.ai_recommendation = ai_result["remediation"]
        
        # For CREATE and TAMPER_EVENTS, call mark_requires_admin_approval
        if event.event_type == "create" or event.event_type in TAMPER_EVENTS:
            mark_requires_admin_approval(event, self.config)
        
        # Log warning if admin approval is required (non-interactive - web UI handles approval)
        if event.requires_admin_approval:
            logger.warning("ADMIN APPROVAL REQUIRED for event %s (path=%s, risk_score=%s)", 
                          event.event_type, 
                          getattr(event, "path", None),
                          getattr(event, "risk_score", None))
            # Ensure flags are set correctly - web UI will handle actual approval
            event.requires_admin_approval = True
            event.admin_approved = False
        
        # Persist event before notifying callback
        self.storage.record_event(event)
        self.callback(event)


def run_watcher(config: Config, storage: Storage, callback: HandlerCallback) -> None:
    """Start observers for configured directories and run until interrupted."""
    observer = Observer()
    for directory in config.monitored_directories:
        root = Path(directory).resolve()
        if not root.exists():
            continue
        handler = WatchHandler(config, storage, callback)
        observer.schedule(handler, str(root), recursive=True)

    observer.start()
    try:
        while True:
            observer.join(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


__all__ = ["run_watcher", "WatchHandler"]

