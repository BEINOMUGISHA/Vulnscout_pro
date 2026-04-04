"""
auth/ — VulnScout Pro Authentication Package

Public API:

    from auth.auth_manager import get_auth_manager, AuthManager
    from auth.rbac         import rbac, Permission, Role, require_permission
    from auth.totp         import verify, create_enrollment, TOTPEnrollment
    from auth.session      import SessionStore
    from auth.audit_log    import get_audit_log, AuditLog, AuditEvent

Quick-start (from api/main.py lifespan):
    from auth.auth_manager import get_auth_manager
    app.state.auth = get_auth_manager()
"""

from auth.audit_log   import AuditLog, AuditEvent, get_audit_log
from auth.rbac        import rbac, Permission, Role, require_permission, require_role
from auth.session     import SessionStore
from auth.auth_manager import AuthManager, get_auth_manager, LoginResult, TokenPair
from auth             import totp

__all__ = [
    "AuditLog", "AuditEvent", "get_audit_log",
    "rbac", "Permission", "Role", "require_permission", "require_role",
    "SessionStore",
    "AuthManager", "get_auth_manager", "LoginResult", "TokenPair",
    "totp",
]