from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect


def home(request):
    if request.user.is_authenticated:
        return redirect('customers:list')
    return redirect('accounts:login')


urlpatterns = [
    path('', home, name='home'),
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls', namespace='accounts')),
    path('customers/', include('customers.urls', namespace='customers')),
]
