"""Phase 4 - Authentication and role-based access control.

Two roles: Analyst and Admin. Permissions belong to roles, not to users:

    User -> Role -> Permissions -> Resources

LIMITATIONS (documented in SECURITY_WRITEUP.md): demo credentials are hardcoded,
passwords are stored as plain unsalted SHA-256, and there is no MFA or login
rate-limiting. A real system would use a user database with bcrypt/argon2.
"""
import hashlib

ANALYST = "Analyst"
ADMIN = "Admin"


def _sha(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# Demo users: username -> (sha256 of password, role)
USERS = {
    "analyst": (_sha("analyst123"), ANALYST),
    "admin": (_sha("admin123"), ADMIN),
}

ROLE_PERMISSIONS = {
    ANALYST: {"view_analytics", "view_protected_data", "view_fraud"},
    ADMIN: {"view_analytics", "view_protected_data", "view_fraud",
            "decrypt_data", "view_audit"},
}


def authenticate(username: str, password: str):
    """Return the user's role if the credentials are valid, otherwise None."""
    record = USERS.get((username or "").strip().lower())
    if record and record[0] == _sha(password or ""):
        return record[1]
    return None


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


if __name__ == "__main__":
    for user, pw in [("analyst", "analyst123"), ("admin", "admin123"), ("admin", "wrong")]:
        role = authenticate(user, pw)
        print(f"login {user}/{pw}: role={role}")
    for role in (ANALYST, ADMIN):
        print(role, "->", sorted(ROLE_PERMISSIONS[role]))
