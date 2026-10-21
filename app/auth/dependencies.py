from typing import Optional, List
from fastapi import Request, HTTPException, status, Depends
from app.auth.security import decode_access_token
from app.database.db import get_db

def log_audit_event(action: str, details: str, user_id: Optional[int] = None, ip_address: Optional[str] = None):
    """Record immutable chain of custody audit log entry."""
    with get_db() as conn:
        conn.execute(
            "INSERT INTO audit_logs (action, details, user_id, ip_address) VALUES (?, ?, ?, ?)",
            (action, details, user_id, ip_address or "127.0.0.1")
        )

def get_current_user_optional(request: Request) -> Optional[dict]:
    """Retrieve authenticated user from Authorization header or session cookie."""
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    elif "access_token" in request.cookies:
        token = request.cookies["access_token"]

    if not token:
        return None

    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        return None

    username = payload["sub"]
    with get_db() as conn:
        user = conn.execute("SELECT id, username, full_name, role, is_active FROM users WHERE username = ?", (username,)).fetchone()
        if user and user["is_active"]:
            return dict(user)

    return None

def get_current_user(request: Request) -> dict:
    """Enforce authentication on protected endpoints."""
    user = get_current_user_optional(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def require_roles(allowed_roles: List[str]):
    """Role-Based Access Control (RBAC) dependency factory."""
    def role_checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires one of roles: {', '.join(allowed_roles)}"
            )
        return user
    return role_checker
