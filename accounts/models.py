"""
Custom user model for Communication_LTD.

Per spec:
  - Password stored as HMAC + Salt (NOT bcrypt/argon2 — the assignment requires HMAC).
  - Password history retained (config-driven count).
  - Login attempts counter for lockout.
  - SHA-1 reset token (per spec).

NOTE: HMAC for password storage is a *deliberate* requirement of this assignment.
In production, use Argon2 or bcrypt. SHA-1 is also broken; assignment-mandated.
"""
from django.db import models
from django.utils import timezone


class User(models.Model):
    """Custom user. We do NOT use Django's auth.User because the assignment
    requires a specific HMAC+Salt scheme that Django's hasher does not produce
    in the exact form requested."""

    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)

    # HMAC+Salt password fields
    password_salt = models.CharField(max_length=64)   # hex-encoded salt
    password_hmac = models.CharField(max_length=128)  # hex-encoded HMAC digest

    # Login attempt tracking
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    # Reset token (SHA-1 per spec)
    reset_token = models.CharField(max_length=64, blank=True, default='')
    reset_token_expires = models.DateTimeField(null=True, blank=True)

    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'accounts_user'

    def __str__(self):
        return self.username

    # Django session compatibility
    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def is_locked(self):
        if self.locked_until and self.locked_until > timezone.now():
            return True
        return False


class PasswordHistory(models.Model):
    """Stores prior HMAC+Salt pairs so users cannot reuse the last N passwords."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_history')
    password_salt = models.CharField(max_length=64)
    password_hmac = models.CharField(max_length=128)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'accounts_password_history'
        ordering = ['-created_at']
