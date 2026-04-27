"""
Lightweight session-backed auth that mirrors Django's auth API just enough.
We can't use django.contrib.auth directly because we have a custom User model
with a non-standard password field (HMAC+Salt).
"""
from functools import wraps
from django.shortcuts import redirect
from django.utils import timezone

from accounts.models import User

SESSION_KEY = '_communication_ltd_user_id'


def login_user(request, user: User):
    request.session[SESSION_KEY] = user.id
    request.session.set_expiry(60 * 60)  # 1 hour
    user.last_login = timezone.now()
    user.failed_login_attempts = 0
    user.locked_until = None
    user.save(update_fields=['last_login', 'failed_login_attempts', 'locked_until'])


def logout_user(request):
    request.session.pop(SESSION_KEY, None)
    request.session.flush()


def get_current_user(request):
    user_id = request.session.get(SESSION_KEY)
    if not user_id:
        return None
    try:
        return User.objects.get(pk=user_id, is_active=True)
    except User.DoesNotExist:
        return None


def login_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        user = get_current_user(request)
        if user is None:
            return redirect('accounts:login')
        request.current_user = user
        return view_func(request, *args, **kwargs)
    return _wrapped
