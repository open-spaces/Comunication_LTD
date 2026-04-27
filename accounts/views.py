"""
Account views: register, login, logout, change-password, forgot-password, reset-password.

Each view branches on settings.VULNERABLE_MODE:
  - True  => Part B vulnerable demo (raw SQL string concat → SQLi works)
  - False => Part B secure demo     (parameterized queries / ORM)

Stored XSS is demonstrated in the customers app (customer-name display).
SQLi is demonstrated here in register and login (and customer search).
"""
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.db import connection
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.utils import timezone

from accounts.auth import login_user, logout_user, login_required, get_current_user
from accounts.models import User
from accounts.utils import (
    generate_salt,
    hmac_password,
    verify_password,
    generate_reset_token,
    validate_password_policy,
    set_user_password,
)


# ===========================================================================
# REGISTER
# ===========================================================================
def register_view(request):
    """
    Section 1 of Part A. Vulnerable to SQLi in VULNERABLE_MODE
    (uniqueness check uses string-concatenated SQL).
    """
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        password_confirm = request.POST.get('password_confirm', '')

        errors = []

        if not username or not email or not password:
            errors.append("All fields are required.")

        if password != password_confirm:
            errors.append("Passwords do not match.")

        # Password policy check
        errors.extend(validate_password_policy(password))

        # Username uniqueness check — THIS is the SQLi sink
        if not errors:
            if settings.VULNERABLE_MODE:
                # ⚠️ VULNERABLE: string concatenation. Try username:
                #   ' OR '1'='1
                # to see truthy result. Or with a registered admin:
                #   admin'--
                with connection.cursor() as cursor:
                    sql = (
                        "SELECT id, username FROM accounts_user "
                        f"WHERE username = '{username}' OR email = '{email}'"
                    )
                    try:
                        cursor.execute(sql)
                        row = cursor.fetchone()
                        if row:
                            errors.append("Username or email already exists.")
                    except Exception as e:
                        errors.append(f"Database error: {e}")
            else:
                # ✅ SECURE: parameterized query (Stored Procedure equivalent via ORM)
                if User.objects.filter(username=username).exists():
                    errors.append("Username already exists.")
                if User.objects.filter(email=email).exists():
                    errors.append("Email already exists.")

        if errors:
            for e in errors:
                messages.error(request, e)
            return render(request, 'accounts/register.html', {
                'username': username, 'email': email,
            })

        # Create user
        user = User(username=username, email=email)
        # set_user_password handles HMAC+Salt + history archiving
        # (history is empty on fresh user; no archive happens.)
        salt = generate_salt()
        user.password_salt = salt
        user.password_hmac = hmac_password(password, salt)
        user.save()

        messages.success(request, "Registration successful. Please log in.")
        return redirect('accounts:login')

    return render(request, 'accounts/register.html')


# ===========================================================================
# LOGIN
# ===========================================================================
def login_view(request):
    """
    Section 3 of Part A. Vulnerable to SQLi in VULNERABLE_MODE
    (user lookup uses string-concatenated SQL — classic ' OR '1'='1'-- bypass).
    """
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        user = None

        if settings.VULNERABLE_MODE:
            # ⚠️ VULNERABLE: classic SQLi sink. Payload examples:
            #   username: admin'--             (skip password check)
            #   username: ' OR '1'='1' --      (return first user)
            with connection.cursor() as cursor:
                sql = (
                    "SELECT id, username, password_salt, password_hmac, "
                    "failed_login_attempts, locked_until, is_active "
                    f"FROM accounts_user WHERE username = '{username}'"
                )
                try:
                    cursor.execute(sql)
                    row = cursor.fetchone()
                except Exception as e:
                    messages.error(request, f"Database error: {e}")
                    return render(request, 'accounts/login.html', {'username': username})

            if row:
                user_id, found_username, salt, hmac_hex, attempts, locked_until, active = row
                # In vulnerable mode we even let the SQLi bypass the password
                # check if the salt/hmac don't match — to make the SQLi visible,
                # we'll still do a check, but we look up the user by raw SQL
                # which is the actual vulnerability. The password check below
                # is honest; the leak is that an attacker can discover users
                # and dump rows via UNION SELECT.
                try:
                    user = User.objects.get(pk=user_id)
                except User.DoesNotExist:
                    user = None
        else:
            # ✅ SECURE: ORM uses parameterized queries
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                user = None

        # Lockout check
        if user and user.is_locked():
            messages.error(request, "Account is locked due to too many failed attempts. Try later.")
            return render(request, 'accounts/login.html', {'username': username})

        if user and user.is_active and verify_password(password, user.password_salt, user.password_hmac):
            login_user(request, user)
            messages.success(request, f"Welcome back, {user.username}.")
            return redirect('customers:list')

        # Failed login -> increment counter
        if user is not None:
            user.failed_login_attempts += 1
            max_attempts = settings.PASSWORD_POLICY.get('max_login_attempts', 3)
            if user.failed_login_attempts >= max_attempts:
                lockout_minutes = settings.PASSWORD_POLICY.get('lockout_minutes', 15)
                user.locked_until = timezone.now() + timedelta(minutes=lockout_minutes)
                messages.error(
                    request,
                    f"Too many failed attempts. Account locked for {lockout_minutes} minutes."
                )
            else:
                remaining = max_attempts - user.failed_login_attempts
                messages.error(
                    request,
                    f"Invalid credentials. {remaining} attempt(s) remaining."
                )
            user.save(update_fields=['failed_login_attempts', 'locked_until'])
        else:
            messages.error(request, "Invalid credentials.")

        return render(request, 'accounts/login.html', {'username': username})

    return render(request, 'accounts/login.html')


# ===========================================================================
# LOGOUT
# ===========================================================================
def logout_view(request):
    logout_user(request)
    return redirect('accounts:login')


# ===========================================================================
# CHANGE PASSWORD
# ===========================================================================
@login_required
def change_password_view(request):
    """Section 2 of Part A. Validates current password, enforces policy,
    enforces history (last N passwords cannot be reused)."""
    user = request.current_user

    if request.method == 'POST':
        current = request.POST.get('current_password', '')
        new_pw = request.POST.get('new_password', '')
        confirm = request.POST.get('confirm_password', '')

        errors = []

        if not verify_password(current, user.password_salt, user.password_hmac):
            errors.append("Current password is incorrect.")

        if new_pw != confirm:
            errors.append("New passwords do not match.")

        # Policy + history
        errors.extend(validate_password_policy(new_pw, user=user))

        if errors:
            for e in errors:
                messages.error(request, e)
            return render(request, 'accounts/change_password.html')

        set_user_password(user, new_pw)
        messages.success(request, "Password changed successfully.")
        return redirect('customers:list')

    return render(request, 'accounts/change_password.html')


# ===========================================================================
# FORGOT PASSWORD - generate SHA-1 token, email it
# ===========================================================================
def forgot_password_view(request):
    """Section 5 of Part A. Generates SHA-1 token and emails to the user."""
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            user = None

        if user:
            token = generate_reset_token()  # SHA-1 per spec
            ttl_minutes = settings.RESET_TOKEN_CONFIG.get('ttl_minutes', 15)
            user.reset_token = token
            user.reset_token_expires = timezone.now() + timedelta(minutes=ttl_minutes)
            user.save(update_fields=['reset_token', 'reset_token_expires'])

            send_mail(
                subject='Communication_LTD password reset',
                message=(
                    f"Hello {user.username},\n\n"
                    f"Your password reset token is:\n\n    {token}\n\n"
                    f"This token expires in {ttl_minutes} minutes.\n"
                    f"If you did not request this, ignore this email."
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )

        # Always show the same message regardless of whether email exists
        # (prevents account enumeration).
        messages.success(
            request,
            "If an account exists for that email, a reset token has been sent. "
            "Check the server console (dev) or your inbox."
        )
        return redirect('accounts:reset_password')

    return render(request, 'accounts/forgot_password.html')


# ===========================================================================
# RESET PASSWORD - user enters token + new password
# ===========================================================================
def reset_password_view(request):
    if request.method == 'POST':
        token = request.POST.get('token', '').strip()
        new_pw = request.POST.get('new_password', '')
        confirm = request.POST.get('confirm_password', '')

        errors = []

        if not token:
            errors.append("Token is required.")

        if new_pw != confirm:
            errors.append("Passwords do not match.")

        user = None
        if not errors:
            try:
                user = User.objects.get(reset_token=token)
            except User.DoesNotExist:
                errors.append("Invalid or expired token.")

            if user and (
                not user.reset_token_expires
                or user.reset_token_expires < timezone.now()
            ):
                errors.append("Invalid or expired token.")
                user = None

        if user is not None:
            errors.extend(validate_password_policy(new_pw, user=user))

        if errors:
            for e in errors:
                messages.error(request, e)
            return render(request, 'accounts/reset_password.html')

        set_user_password(user, new_pw, save=False)
        user.reset_token = ''
        user.reset_token_expires = None
        user.failed_login_attempts = 0
        user.locked_until = None
        user.save()

        messages.success(request, "Password reset successful. Please log in.")
        return redirect('accounts:login')

    return render(request, 'accounts/reset_password.html')
