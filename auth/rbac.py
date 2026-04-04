"""
auth/rbac.py — Role-Based Access Control

Defines the complete permission model for VulnScout Pro.
Three roles form a strict hierarchy — each role inherits all
permissions of the role below it.

Role hierarchy (most → least privileged):
  admin    ⊃ analyst ⊃ readonly

Permission taxonomy:
  scan:*        — scan lifecycle operations
  report:*      — report generation and access
  target:*      — target management
  finding:*     — finding access and annotation
  user:*        — user account management (admin only)
  api_key:*     — API key management
  audit:*       — audit log access (admin only)
  config:*      — configuration read (admin only)
  resource:*    — cross-cutting resource operations

API key scopes are a subset of the role's permissions.
An API key can never grant more rights than the issuing role.

Usage:
    from auth.rbac import rbac, Permission, Role

    # Check a permission
    if rbac.can(user.role, Permission.SCAN_CREATE):
        ...

    # Get all permissions for a role
    perms = rbac.permissions_for(Role.ANALYST)

    # Check scope subset (for API key validation)
    if rbac.scope_subset(requested_scopes, user.role):
        ...

    # FastAPI dependency
    async def require_permission(perm: Permission):
        def _dep(user = Depends(require_auth)):
            rbac.enforce(user.role, perm, user.user_id)
            return user
        return _dep
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, FrozenSet, List, Optional, Set

logger = logging.getLogger(__name__)


# ── Role definitions ───────────────────────────────────────────────

class Role(str, Enum):
    ADMIN    = "admin"
    ANALYST  = "analyst"
    READONLY = "readonly"

    @classmethod
    def from_str(cls, value: str) -> "Role":
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(
                f"Invalid role {value!r}. Must be one of: "
                + ", ".join(r.value for r in cls)
            )

    def rank(self) -> int:
        """Higher rank = more privileged."""
        return {self.ADMIN: 3, self.ANALYST: 2, self.READONLY: 1}[self]

    def __ge__(self, other: "Role") -> bool:
        return self.rank() >= other.rank()

    def __gt__(self, other: "Role") -> bool:
        return self.rank() > other.rank()

    def __le__(self, other: "Role") -> bool:
        return self.rank() <= other.rank()

    def __lt__(self, other: "Role") -> bool:
        return self.rank() < other.rank()


# ── Permission definitions ─────────────────────────────────────────

class Permission(str, Enum):
    """
    Granular permissions. Values are the string scope names used in
    JWT payloads and API key scope lists.
    """
    # Scan permissions
    SCAN_READ       = "scan:read"       # View scan results
    SCAN_CREATE     = "scan:create"     # Submit new scans
    SCAN_CANCEL     = "scan:cancel"     # Cancel running scans
    SCAN_DELETE     = "scan:delete"     # Delete scan records

    # Report permissions
    REPORT_READ     = "report:read"     # View and download reports
    REPORT_CREATE   = "report:create"   # Generate new reports
    REPORT_DELETE   = "report:delete"   # Delete reports

    # Target permissions
    TARGET_READ     = "target:read"     # View targets
    TARGET_CREATE   = "target:create"   # Create / update targets
    TARGET_DELETE   = "target:delete"   # Delete targets (admin)

    # Finding permissions
    FINDING_READ    = "finding:read"    # View findings
    FINDING_ANNOTATE = "finding:annotate"  # Add notes, mark FP

    # API key permissions
    API_KEY_CREATE  = "api_key:create"  # Issue API keys
    API_KEY_REVOKE  = "api_key:revoke"  # Revoke own API keys
    API_KEY_MANAGE  = "api_key:manage"  # Revoke any user's keys (admin)

    # User management (admin only)
    USER_READ       = "user:read"       # List and view user accounts
    USER_CREATE     = "user:create"     # Create new accounts
    USER_UPDATE     = "user:update"     # Change roles, reset passwords
    USER_DELETE     = "user:delete"     # Delete accounts

    AUDIT_READ      = "audit:read"      # View audit log
    AUDIT_EXPORT    = "audit:export"    # Export audit log for compliance

    # Team management
    TEAM_READ       = "team:read"       # View team members and assets
    TEAM_MANAGE     = "team:manage"     # Add/remove members, change roles

    # Configuration
    CONFIG_READ     = "config:read"     # Read running configuration

    # Cross-cutting
    RESOURCE_DELETE = "resource:delete" # Generic delete (used as a guard)


# ── Permission matrix ──────────────────────────────────────────────

_READONLY_PERMS: FrozenSet[Permission] = frozenset([
    Permission.SCAN_READ,
    Permission.REPORT_READ,
    Permission.TARGET_READ,
    Permission.FINDING_READ,
])

_ANALYST_PERMS: FrozenSet[Permission] = _READONLY_PERMS | frozenset([
    Permission.SCAN_CREATE,
    Permission.SCAN_CANCEL,
    Permission.REPORT_CREATE,
    Permission.TARGET_CREATE,
    Permission.FINDING_ANNOTATE,
    Permission.API_KEY_CREATE,
    Permission.API_KEY_REVOKE,
    Permission.TEAM_READ,
])

_ADMIN_PERMS: FrozenSet[Permission] = _ANALYST_PERMS | frozenset([
    Permission.SCAN_DELETE,
    Permission.REPORT_DELETE,
    Permission.TARGET_DELETE,
    Permission.API_KEY_MANAGE,
    Permission.USER_READ,
    Permission.USER_CREATE,
    Permission.USER_UPDATE,
    Permission.USER_DELETE,
    Permission.AUDIT_READ,
    Permission.AUDIT_EXPORT,
    Permission.TEAM_MANAGE,
    Permission.CONFIG_READ,
    Permission.RESOURCE_DELETE,
])

_ROLE_PERMISSIONS: Dict[Role, FrozenSet[Permission]] = {
    Role.READONLY: _READONLY_PERMS,
    Role.ANALYST:  _ANALYST_PERMS,
    Role.ADMIN:    _ADMIN_PERMS,
}

# What permissions can appear in API keys for each role
# (same as role perms — keys can never exceed their issuer's role)
_API_KEY_ALLOWED_SCOPES: Dict[Role, FrozenSet[Permission]] = _ROLE_PERMISSIONS


# ── Resource ownership rules ───────────────────────────────────────

@dataclass(frozen=True)
class ResourcePolicy:
    """
    Defines who can perform operations on a resource type.
    owner_can: permissions the resource owner has (regardless of role)
    admin_only: permissions that require admin role even for resource owners
    """
    resource_type: str
    owner_can:     FrozenSet[Permission]
    admin_only:    FrozenSet[Permission]


_RESOURCE_POLICIES: Dict[str, ResourcePolicy] = {
    "scan": ResourcePolicy(
        resource_type="scan",
        owner_can=frozenset([
            Permission.SCAN_READ,
            Permission.SCAN_CANCEL,
            Permission.REPORT_CREATE,
        ]),
        admin_only=frozenset([Permission.SCAN_DELETE]),
    ),
    "report": ResourcePolicy(
        resource_type="report",
        owner_can=frozenset([
            Permission.REPORT_READ,
            Permission.REPORT_DELETE,
        ]),
        admin_only=frozenset(),
    ),
    "target": ResourcePolicy(
        resource_type="target",
        owner_can=frozenset([
            Permission.TARGET_READ,
            Permission.TARGET_CREATE,
        ]),
        admin_only=frozenset([Permission.TARGET_DELETE]),
    ),
    "api_key": ResourcePolicy(
        resource_type="api_key",
        owner_can=frozenset([
            Permission.API_KEY_REVOKE,
        ]),
        admin_only=frozenset([Permission.API_KEY_MANAGE]),
    ),
}


# ── RBAC engine ────────────────────────────────────────────────────

class RBACEngine:
    """
    Centralised permission evaluation engine.

    All permission checks flow through this class so that
    policy changes affect the whole codebase.
    """

    def can(self, role: str, permission: Permission) -> bool:
        """
        Return True if the given role has the requested permission.
        """
        try:
            r = Role.from_str(role)
        except ValueError:
            return False
        return permission in _ROLE_PERMISSIONS.get(r, frozenset())

    def permissions_for(self, role: str) -> FrozenSet[Permission]:
        """Return the complete permission set for a role."""
        try:
            r = Role.from_str(role)
            return _ROLE_PERMISSIONS.get(r, frozenset())
        except ValueError:
            return frozenset()

    def scopes_for(self, role: str) -> List[str]:
        """Return permission values as strings (for JWT scope claims)."""
        return [p.value for p in self.permissions_for(role)]

    def can_access_resource(
        self,
        role:       str,
        permission: Permission,
        resource_owner_id: str,
        actor_id:   str,
        resource_team_id: Optional[str] = None,
        actor_team_id:    Optional[str] = None,
    ) -> bool:
        """
        Determine if an actor can perform a permission on a resource,
        considering role, ownership, and team membership.

        Logic:
          1. Admin: Always permitted if role has permission
          2. Resource Owner: Permitted if policy allows 'owner_can'
          3. Team Member: Permitted if policy allows 'owner_can' AND actor belongs to resource team
          4. admin_only: Never permitted for non-admins
        """
        try:
            r = Role.from_str(role)
        except ValueError:
            return False

        # Admin always wins (within role permission matrix)
        if r == Role.ADMIN:
            return permission in _ADMIN_PERMS

        # Non-admin: check role permission first
        if permission not in _ROLE_PERMISSIONS.get(r, frozenset()):
            return False

        # Check resource ownership for delete/modify operations
        resource_type = _permission_to_resource(permission)
        if resource_type:
            policy = _RESOURCE_POLICIES.get(resource_type)
            if policy:
                if permission in policy.admin_only:
                    return False  # Admin only
                if permission in policy.owner_can:
                    # Owned by actor OR shared with actor's team
                    is_owner = actor_id == resource_owner_id
                    is_team_member = (resource_team_id and resource_team_id == actor_team_id)
                    return is_owner or is_team_member
        return True

    def enforce(
        self,
        role:        str,
        permission:  Permission,
        actor_id:    str = "",
        resource_id: str = "",
        ip_address:  str = "",
    ) -> None:
        """
        Assert that a role has a permission. Raises PermissionError if not.
        Records a RBAC denial to the audit log on failure.
        """
        if not self.can(role, permission):
            self._record_denial(actor_id, ip_address, role, permission)
            raise PermissionError(
                f"Role {role!r} does not have permission {permission.value!r}."
            )

    def enforce_resource(
        self,
        role:              str,
        permission:        Permission,
        resource_owner_id: str,
        actor_id:          str,
        ip_address:        str = "",
    ) -> None:
        """
        Assert resource-level access. Raises PermissionError if denied.
        """
        if not self.can_access_resource(role, permission, resource_owner_id, actor_id):
            self._record_denial(actor_id, ip_address, role, permission)
            raise PermissionError(
                f"Role {role!r} does not have {permission.value!r} "
                f"on resource owned by {resource_owner_id[:8]}."
            )

    def scope_subset(
        self,
        requested_scopes: List[str],
        role:             str,
    ) -> tuple[bool, List[str]]:
        """
        Validate that requested_scopes are all within the role's allowed scopes.
        Used when creating API keys to prevent privilege escalation.

        Returns (is_valid, invalid_scopes).
        """
        try:
            r = Role.from_str(role)
        except ValueError:
            return False, requested_scopes

        allowed   = {p.value for p in _API_KEY_ALLOWED_SCOPES.get(r, frozenset())}
        invalid   = [s for s in requested_scopes if s not in allowed]
        return len(invalid) == 0, invalid

    def validate_api_key_scopes(
        self, requested: List[str], issuer_role: str
    ) -> List[str]:
        """
        Return the intersection of requested scopes with the issuer role's
        allowed scopes. Never grants more than the issuing role has.
        """
        try:
            r = Role.from_str(issuer_role)
        except ValueError:
            return []
        allowed = {p.value for p in _API_KEY_ALLOWED_SCOPES.get(r, frozenset())}
        return [s for s in requested if s in allowed]

    def _record_denial(
        self, actor_id: str, ip: str, role: str, permission: Permission
    ) -> None:
        """Fire-and-forget audit log entry for permission denial."""
        try:
            from auth.audit_log import get_audit_log, AuditEvent, OUTCOME_BLOCKED
            audit = get_audit_log()
            audit.log(AuditEvent(
                event_type="rbac.denied",
                outcome=OUTCOME_BLOCKED,
                actor_id=actor_id or "unknown",
                ip_address=ip or "unknown",
                detail={
                    "role":       role,
                    "permission": permission.value,
                },
            ))
        except Exception:
            pass  # Never let audit failure block the permission response

    # ── Convenience role checks ─────────────────────────────────────

    def is_admin(self, role: str) -> bool:
        try:
            return Role.from_str(role) == Role.ADMIN
        except ValueError:
            return False

    def is_analyst_or_above(self, role: str) -> bool:
        try:
            return Role.from_str(role) >= Role.ANALYST
        except ValueError:
            return False

    def role_rank(self, role: str) -> int:
        """Return numeric rank: admin=3, analyst=2, readonly=1, invalid=0."""
        try:
            return Role.from_str(role).rank()
        except ValueError:
            return 0

    def can_assign_role(self, actor_role: str, target_role: str) -> bool:
        """
        An admin can assign any role.
        No other role can change roles.
        """
        try:
            actor = Role.from_str(actor_role)
            Role.from_str(target_role)   # Validate target is a real role
        except ValueError:
            return False
        return actor == Role.ADMIN

    def summary(self) -> Dict:
        """Return a human-readable summary of the permission matrix."""
        return {
            role.value: sorted([p.value for p in perms])
            for role, perms in _ROLE_PERMISSIONS.items()
        }


# ── Helper ─────────────────────────────────────────────────────────

def _permission_to_resource(perm: Permission) -> Optional[str]:
    """Map a permission to its resource type for ownership checks."""
    prefix_map = {
        "scan:":     "scan",
        "report:":   "report",
        "target:":   "target",
        "api_key:":  "api_key",
    }
    for prefix, resource in prefix_map.items():
        if perm.value.startswith(prefix):
            return resource
    return None


# ── Module singleton ───────────────────────────────────────────────

rbac = RBACEngine()
"""
Module-level RBAC engine singleton.
Import and use directly:
    from auth.rbac import rbac, Permission
    rbac.enforce(user.role, Permission.SCAN_CREATE)
"""


# ── FastAPI dependency factories ───────────────────────────────────

def require_permission(permission: Permission):
    """
    FastAPI dependency factory that enforces a specific permission.

    Usage:
        @router.post("/scans")
        async def create_scan(
            user: AuthenticatedUser = Depends(require_permission(Permission.SCAN_CREATE))
        ):
            ...
    """
    from fastapi import Depends, HTTPException, Request, status
    from api.dependencies import require_auth, AuthenticatedUser

    async def _dep(
        request: Request,
        user: AuthenticatedUser = Depends(require_auth),
    ) -> AuthenticatedUser:
        if not rbac.can(user.role, permission):
            rbac._record_denial(
                user.user_id,
                getattr(request.client, "host", "unknown"),
                user.role,
                permission,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Permission {permission.value!r} required. "
                    f"Your role ({user.role!r}) does not have this permission."
                ),
            )
        return user

    return _dep


def require_role(minimum_role: Role):
    """
    FastAPI dependency that enforces a minimum role level.

    Usage:
        @router.delete("/users/{id}")
        async def delete_user(user = Depends(require_role(Role.ADMIN))):
            ...
    """
    from fastapi import Depends, HTTPException, status
    from api.dependencies import require_auth, AuthenticatedUser

    async def _dep(
        user: AuthenticatedUser = Depends(require_auth),
    ) -> AuthenticatedUser:
        if rbac.role_rank(user.role) < minimum_role.rank():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Minimum role required: {minimum_role.value!r}. "
                    f"Your role is {user.role!r}."
                ),
            )
        return user

    return _dep