"""
Domain model for Comunication_LTD:
  - Sector: market segments (e.g., Home, Business, Education)
  - InternetPackage: browsing packages sold to customers
  - Customer: a customer of the company
"""
from django.db import models


class Sector(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    class Meta:
        db_table = 'customers_sector'

    def __str__(self):
        return self.name


class InternetPackage(models.Model):
    name = models.CharField(max_length=100, unique=True)
    speed_mbps = models.IntegerField()
    monthly_price = models.DecimalField(max_digits=8, decimal_places=2)
    description = models.TextField(blank=True)

    class Meta:
        db_table = 'customers_package'

    def __str__(self):
        return f"{self.name} ({self.speed_mbps} Mbps)"


class Customer(models.Model):
    full_name = models.CharField(max_length=200)
    email = models.EmailField()
    phone = models.CharField(max_length=30, blank=True)
    address = models.CharField(max_length=300, blank=True)

    sector = models.ForeignKey(Sector, on_delete=models.SET_NULL, null=True, blank=True)
    package = models.ForeignKey(InternetPackage, on_delete=models.SET_NULL, null=True, blank=True)

    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        'accounts.User', on_delete=models.SET_NULL, null=True, blank=True
    )

    class Meta:
        db_table = 'customers_customer'
        ordering = ['-created_at']

    def __str__(self):
        return self.full_name
