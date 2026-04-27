"""
Crypto + password policy utilities.

Implements the assignment's exact requirements:
  - HMAC + Salt for password storage (algorithm from config; default sha256)
  - SHA-1 for password reset token (per spec)
  - Password complexity check driven by config.json
  - Dictionary check
  - History check
"""
import hashlib
import hmac
import os
import secrets
import string
from pathlib import Path

from django.conf import settings


# ---------------------------------------------------------------------------
# Password storage: HMAC + Salt
# ---------------------------------------------------------------------------
def generate_salt() -> str:
    """Cryptographically random salt, hex-encoded."""
    n_bytes = settings.HMAC_CONFIG.get('salt_bytes', 16)
    return secrets.token_hex(n_bytes)


def hmac_password(password: str, salt_hex: str) -> str:
    """
    Compute HMAC(salt, password) using the configured algorithm.
    Returns hex digest.

    The salt acts as the HMAC key, the password as the message — this is the
    most common interpretation of 'HMAC + Salt' in coursework contexts.
    """
    algo = settings.HMAC_CONFIG.get('algorithm', 'sha256')
    salt_bytes = bytes.fromhex(salt_hex)
    return hmac.new(salt_bytes, password.encode('utf-8'), algo).hexdigest()


def verify_password(password: str, salt_hex: str, expected_hmac: str) -> bool:
    """Constant-time HMAC comparison."""
    computed = hmac_password(password, salt_hex)
    return hmac.compare_digest(computed, expected_hmac)


# ---------------------------------------------------------------------------
# Reset token: SHA-1 (per spec)
# ---------------------------------------------------------------------------
def generate_reset_token() -> str:
    """
    Generate a random value and hash it with SHA-1, per spec.
    Returns the hex digest (40 chars).
    """
    random_value = secrets.token_bytes(32)
    digest = hashlib.sha1(random_value).hexdigest()
    return digest


# ---------------------------------------------------------------------------
# Password policy validation
# ---------------------------------------------------------------------------
_DICTIONARY_CACHE = None


def _load_dictionary():
    global _DICTIONARY_CACHE
    if _DICTIONARY_CACHE is not None:
        return _DICTIONARY_CACHE

    policy = settings.PASSWORD_POLICY
    dict_file = policy.get('dictionary_file', 'common_passwords.txt')
    dict_path = Path(settings.BASE_DIR) / dict_file

    words = set()
    if dict_path.exists():
        with open(dict_path, 'r', encoding='utf-8') as f:
            for line in f:
                w = line.strip()
                if w:
                    words.add(w.lower())

    _DICTIONARY_CACHE = words
    return words


def validate_password_policy(password: str, user=None) -> list:
    """
    Validate against the policy in config.json.
    Returns a list of error messages. Empty list = valid.
    """
    policy = settings.PASSWORD_POLICY
    errors = []

    if len(password) < policy.get('min_length', 10):
        errors.append(f"Password must be at least {policy['min_length']} characters long.")

    if policy.get('require_uppercase') and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter.")

    if policy.get('require_lowercase') and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter.")

    if policy.get('require_digits') and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit.")

    if policy.get('require_special'):
        special_chars = policy.get('special_chars', string.punctuation)
        if not any(c in special_chars for c in password):
            errors.append("Password must contain at least one special character.")

    if policy.get('dictionary_check'):
        if password.lower() in _load_dictionary():
            errors.append("Password is too common. Choose a less guessable password.")

    if user is not None and policy.get('history_count', 0) > 0:
        from accounts.models import PasswordHistory
        history = PasswordHistory.objects.filter(user=user).order_by('-created_at')[
            : policy['history_count']
        ]
        for old in history:
            if verify_password(password, old.password_salt, old.password_hmac):
                errors.append(
                    f"Password was used recently. Choose a password not used in the last "
                    f"{policy['history_count']} changes."
                )
                break

        # Also check against the current password
        if verify_password(password, user.password_salt, user.password_hmac):
            errors.append("New password must differ from the current password.")

    return errors


def set_user_password(user, raw_password: str, save: bool = True):
    """Set a new password on a user, archiving the previous one to history."""
    from accounts.models import PasswordHistory

    # Archive the old password (if it exists) before overwriting
    if user.password_hmac:
        PasswordHistory.objects.create(
            user=user,
            password_salt=user.password_salt,
            password_hmac=user.password_hmac,
        )

    salt = generate_salt()
    user.password_salt = salt
    user.password_hmac = hmac_password(raw_password, salt)

    # Trim history beyond policy
    keep = settings.PASSWORD_POLICY.get('history_count', 3)
    extras = PasswordHistory.objects.filter(user=user).order_by('-created_at')[keep:]
    PasswordHistory.objects.filter(pk__in=[e.pk for e in extras]).delete()

    if save:
        user.save()
