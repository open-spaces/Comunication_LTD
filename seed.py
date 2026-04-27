"""
Seed Comunication_LTD with example sectors and internet packages.
Run: python manage.py shell < seed.py
Or:  python seed.py  (after setting DJANGO_SETTINGS_MODULE)
"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'communication_ltd.settings')
django.setup()

from customers.models import Sector, InternetPackage  # noqa: E402

SECTORS = [
    ('Home', 'Residential customers'),
    ('Business', 'Small and medium businesses'),
    ('Enterprise', 'Large corporate clients'),
    ('Education', 'Schools and universities'),
    ('Government', 'Public sector entities'),
]

PACKAGES = [
    ('Basic', 50, 49.90, 'Entry-level home browsing'),
    ('Plus', 200, 79.90, 'For streaming households'),
    ('Pro', 500, 119.90, 'Power users and remote workers'),
    ('Business 1G', 1000, 249.90, 'Symmetric gigabit for offices'),
    ('Enterprise 10G', 10000, 1499.90, 'Dedicated multi-gig fiber'),
]

for name, desc in SECTORS:
    Sector.objects.get_or_create(name=name, defaults={'description': desc})

for name, speed, price, desc in PACKAGES:
    InternetPackage.objects.get_or_create(
        name=name,
        defaults={'speed_mbps': speed, 'monthly_price': price, 'description': desc},
    )

print(f"Seeded {Sector.objects.count()} sectors, {InternetPackage.objects.count()} packages.")
