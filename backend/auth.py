"""Authentication and RBAC service for the Pocket Packet Sniffer (PPS).

Implements security requirements:
- SEC-REQ-2: User authentication with credentials (passwords >= 10 chars)
- SEC-REQ-3: Role-Based Access Control (Field Engineer vs Administrator)
- SEC-REQ-6: Account lockout for 5 minutes after 5 consecutive failed login attempts
"""

from datetime import datetime, timezone, timedelta
import hashlib
import secrets

LOCKOUT_DURATION = timedelta(minutes=5)
MAX_FAILED_ATTEMPTS = 5
MIN_PASSWORD_LENGTH = 10

# Seed default users with >= 10 character passwords (SEC-REQ-2)
DEFAULT_USERS = {
    "admin": {
        "username": "admin",
        "password_hash": hashlib.sha256("AdminPass123!".encode()).hexdigest(),
        "role": "admin",
    },
    "engineer": {
        "username": "engineer",
        "password_hash": hashlib.sha256("EngineerPass123!".encode()).hexdigest(),
        "role": "field_engineer",
    },
}


class AuthService:
    def __init__(self) -> None:
        self._users = dict(DEFAULT_USERS)
        self._failed_attempts = {}     # username -> int
        self._lockout_until = {}       # username -> datetime (UTC)
        self._sessions = {}            # token -> dict(username, role, expires)

    def is_locked(self, username: str) -> bool:
        """Check if an account is currently locked out."""
        until = self._lockout_until.get(username)
        if not until:
            return False
        now = datetime.now(timezone.utc)
        if now < until:
            return True
        # Lockout period expired; reset counters
        self._lockout_until.pop(username, None)
        self._failed_attempts[username] = 0
        return False

    def get_remaining_lockout_seconds(self, username: str) -> int:
        """Return remaining lockout seconds, or 0 if not locked."""
        until = self._lockout_until.get(username)
        if not until:
            return 0
        now = datetime.now(timezone.utc)
        diff = (until - now).total_seconds()
        return max(0, int(diff))

    def authenticate(self, username: str, password: str) -> dict:
        """Authenticate user credentials and return a session token or raise error."""
        if not username or not password:
            raise ValueError("Username and password are required")

        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

        if self.is_locked(username):
            rem = self.get_remaining_lockout_seconds(username)
            raise PermissionError(f"Account is locked due to repeated failed logins. Try again in {rem} seconds.")

        user = self._users.get(username)
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()

        if not user or user["password_hash"] != pwd_hash:
            # Register failed attempt
            current_fails = self._failed_attempts.get(username, 0) + 1
            self._failed_attempts[username] = current_fails
            if current_fails >= MAX_FAILED_ATTEMPTS:
                self._lockout_until[username] = datetime.now(timezone.utc) + LOCKOUT_DURATION
                raise PermissionError("Account locked for 5 minutes after 5 consecutive failed attempts")
            remaining = MAX_FAILED_ATTEMPTS - current_fails
            raise ValueError(f"Invalid username or password. {remaining} attempt(s) remaining before lockout.")

        # Success: reset failures and create session
        self._failed_attempts[username] = 0
        token = secrets.token_hex(24)
        expires = datetime.now(timezone.utc) + timedelta(hours=8)
        session_data = {
            "username": user["username"],
            "role": user["role"],
            "expires": expires,
        }
        self._sessions[token] = session_data

        return {
            "token": token,
            "user": {
                "username": user["username"],
                "role": user["role"],
            },
        }

    def validate_session(self, token: str) -> dict | None:
        """Validate session token and return user metadata, or None if expired/invalid."""
        if not token:
            return None
        session = self._sessions.get(token)
        if not session:
            return None
        if datetime.now(timezone.utc) > session["expires"]:
            self._sessions.pop(token, None)
            return None
        return {
            "username": session["username"],
            "role": session["role"],
        }

    def logout(self, token: str) -> bool:
        """Invalidate an active session."""
        if token in self._sessions:
            del self._sessions[token]
            return True
        return False
