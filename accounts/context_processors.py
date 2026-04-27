from django.conf import settings
from accounts.auth import get_current_user


def vulnerable_mode(request):
    return {
        'VULNERABLE_MODE': settings.VULNERABLE_MODE,
        'current_user': get_current_user(request),
    }
