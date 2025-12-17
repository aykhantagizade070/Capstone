"""FastAPI endpoints for FIM agent web interface."""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Body, Cookie, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from fim_agent.core.config import Config
from fim_agent.core.storage import Storage
from fim_agent.core.events import Event


class AdminApprovalRequest(BaseModel):
    """Request model for admin approval endpoint."""
    password: str
    approve: bool = True


class AdminApproveRequest(BaseModel):
    """Request model for admin approval endpoint."""
    password: str


def create_app(config: Config) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="FIM Agent API",
        description="File Integrity Monitoring Agent REST API",
        version="1.0.0",
    )

    # Enable CORS for frontend development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, restrict to specific origins
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Initialize storage connection
    storage = Storage(config.database_path)
    storage.init_schema()

    # In-memory session store (simple demo - not production-ready)
    active_sessions: Dict[str, str] = {}

    def get_dashboard_password() -> Optional[str]:
        """Get dashboard password from environment, fallback to admin password."""
        return os.environ.get("FIM_DASHBOARD_PASSWORD") or os.environ.get(config.admin_password_env_var)

    def require_auth(request: Request, fim_session: Optional[str] = Cookie(None)) -> bool:
        """
        Lightweight auth dependency.
        If FIM_DASHBOARD_PASSWORD is not set, skip auth (for local/dev).
        If it is set, require valid session cookie.
        """
        dashboard_password = get_dashboard_password()
        if not dashboard_password:
            # No password requirement - allow access
            return True
        
        # Check session cookie
        if not fim_session or fim_session not in active_sessions:
            raise HTTPException(status_code=401, detail="Unauthorized - please login")
        
        return True

    def event_to_dict(event: Event) -> Dict[str, Any]:
        """Convert Event to API response dict."""
        return {
            "id": getattr(event, "id", None),  # Will be set if fetched with ID
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "path": event.path,
            "old_path": event.old_path,
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
            "mitre_tags": event.mitre_tags,
            "message": event.message,
            "alert": event.is_alert if event.is_alert is not None else False,
            "requires_admin_approval": event.requires_admin_approval if event.requires_admin_approval is not None else False,
            "admin_approved": event.admin_approved,
            "content_score": event.content_score,
            "content_flags": event.content_flags,
            "ai_recommendation": event.ai_recommendation,
            "first_seen": event.first_seen,
            "sticky_private": getattr(event, "sticky_private", None),
            "effective_classification": getattr(event, "effective_classification", None),
        }

    @app.get("/api/events")
    def get_events(
        request: Request,
        severity: Optional[str] = Query(None, description="Filter by severity (low/medium/high)"),
        classification: Optional[str] = Query(None, description="Filter by content_classification"),
        min_risk: Optional[int] = Query(None, description="Minimum risk_score"),
        path_filter: Optional[str] = Query(None, description="Filter by path substring"),
        limit: int = Query(100, ge=1, le=1000, description="Maximum number of events to return"),
        offset: int = Query(0, ge=0, description="Number of events to skip"),
        auth: bool = Depends(require_auth),
    ) -> Dict[str, Any]:
        """
        Get events with optional filtering and pagination.
        Returns events in descending chronological order (newest first).
        """
        # Get optional admin approval filters from query params
        requires_admin_approval_param = request.query_params.get("requires_admin_approval")
        admin_approved_param = request.query_params.get("admin_approved")
        
        events = storage.get_events(
            severity=severity,  # type: ignore[arg-type]
            classification=classification,
            min_risk=min_risk,
            path_filter=path_filter,
            limit=limit,
            offset=offset,
            order_desc=True,
        )
        
        # Filter by admin approval flags if provided
        if requires_admin_approval_param is not None:
            flag = requires_admin_approval_param.lower() == "true"
            events = [ev for ev in events if getattr(ev, "requires_admin_approval", False) == flag]
        
        if admin_approved_param is not None:
            val = admin_approved_param.lower()
            if val == "true":
                events = [ev for ev in events if getattr(ev, "admin_approved", None) is True]
            elif val == "false":
                # Treat NULL as "not approved" (pending) as well as explicit false/0
                events = [
                    ev for ev in events
                    if getattr(ev, "admin_approved", None) in (None, False)
                ]
            else:
                # Unknown value - no-op to preserve backward compatibility
                pass
        
        return {
            "events": [event_to_dict(ev) for ev in events],
            "count": len(events),
            "limit": limit,
            "offset": offset,
        }

    @app.get("/api/events/{event_id}")
    def get_event_by_id(event_id: int, auth: bool = Depends(require_auth)) -> Dict[str, Any]:
        """Get a single event by its database ID."""
        event = storage.get_event_by_id(event_id)
        if not event:
            raise HTTPException(status_code=404, detail=f"Event with id {event_id} not found")
        return event_to_dict(event)

    @app.post("/api/events/{event_id}/approve")
    def approve_event(
        event_id: int,
        body: AdminApproveRequest,
        auth: bool = Depends(require_auth),
    ) -> Dict[str, Any]:
        """
        Approve an event that requires admin approval.
        Sets admin_approved = True if password is correct.
        """
        admin_password = (
            os.getenv("FIM_ADMIN_PASSWORD")
            or os.getenv("FIM_DASHBOARD_PASSWORD")
        )
        if not admin_password or body.password != admin_password:
            raise HTTPException(status_code=401, detail="Invalid admin password")

        event = storage.get_event_by_id(event_id)
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")

        if not getattr(event, "requires_admin_approval", False):
            return {"success": False, "detail": "Event does not require admin approval"}

        # Update the event approval status using storage
        updated_event = storage.set_admin_approved(event_id, True)
        if not updated_event:
            raise HTTPException(status_code=404, detail="Event not found")

        # Reuse the existing to_dict() logic / response format
        return {"success": True, "event": event_to_dict(updated_event)}

    @app.get("/api/stats/summary")
    def get_stats_summary(auth: bool = Depends(require_auth)) -> Dict[str, Any]:
        """Get high-level statistics about events."""
        stats = storage.get_stats_summary()
        return stats

    @app.post("/api/login")
    def login(body: Dict[str, Any] = Body(...)) -> Response:
        """
        Login endpoint for dashboard access.
        Accepts username and password, compares password with FIM_DASHBOARD_PASSWORD or FIM_ADMIN_PASSWORD.
        Returns a session token and sets HttpOnly cookie.
        """
        from fastapi.responses import JSONResponse
        
        username = body.get("username", "")  # Username is accepted but not currently used
        password = body.get("password")
        expected_password = get_dashboard_password()
        
        if not expected_password:
            # No password requirement - allow access
            token = str(uuid.uuid4())
            active_sessions[token] = "authenticated"
            response = JSONResponse(content={"token": token, "success": True})
            response.set_cookie(
                key="fim_session",
                value=token,
                httponly=True,
                max_age=3600,  # 1 hour
                samesite="lax"
            )
            return response
        
        if password != expected_password:
            raise HTTPException(status_code=401, detail="Invalid password")
        
        # Generate session token
        token = str(uuid.uuid4())
        active_sessions[token] = "authenticated"
        
        response = JSONResponse(content={"token": token, "success": True})
        response.set_cookie(
            key="fim_session",
            value=token,
            httponly=True,
            max_age=3600,  # 1 hour
            samesite="lax"
        )
        return response

    @app.get("/api/stats/risk_pie")
    def get_risk_pie(auth: bool = Depends(require_auth)) -> Dict[str, int]:
        """
        Get risk score distribution in buckets for pie chart visualization.
        Buckets: low (0-29), medium (30-59), high (60-79), critical (80+)
        """
        return storage.get_risk_pie_stats()

    @app.get("/api/admin/pending")
    def get_pending_admin_events(
        limit: int = Query(10, ge=1, le=100, description="Maximum number of pending events to return"),
        auth: bool = Depends(require_auth),
    ) -> Dict[str, Any]:
        """Get events that require admin approval but haven't been approved yet."""
        events = storage.get_pending_admin_events(limit=limit)
        return {
            "events": [event_to_dict(ev) for ev in events],
            "count": len(events),
        }

    @app.post("/api/admin/approve/{event_id}")
    def approve_event(
        event_id: int,
        body: Dict[str, Any] = Body(...),
        auth: bool = Depends(require_auth),
    ) -> Dict[str, Any]:
        """
        Approve or reject an event requiring admin approval.
        
        Body should contain:
        - password: Admin password from environment variable
        - approved: Boolean indicating approval (true) or rejection (false)
        """
        password = body.get("password")
        approved = body.get("approved", True)
        
        # Verify password
        expected_password = os.getenv(config.admin_password_env_var)
        if not expected_password:
            raise HTTPException(
                status_code=500,
                detail=f"Admin password not configured. Set {config.admin_password_env_var} environment variable."
            )
        
        if password != expected_password:
            raise HTTPException(status_code=401, detail="Invalid admin password")
        
        # Update event approval status
        updated_event = storage.set_admin_approved(event_id, approved)
        if not updated_event:
            raise HTTPException(status_code=404, detail=f"Event with id {event_id} not found")
        
        return {
            "success": True,
            "event": event_to_dict(updated_event),
            "message": "Event approved" if approved else "Event rejected"
        }

    @app.get("/", response_class=HTMLResponse)
    def root() -> str:
        """Serve the FIM dashboard."""
        template_path = Path(__file__).parent / "templates" / "index.html"
        if not template_path.exists():
            return HTMLResponse(
                content="<h1>Dashboard template not found</h1>",
                status_code=500
            )
        return template_path.read_text(encoding="utf-8")

    return app
