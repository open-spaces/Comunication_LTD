"""
Customer views.

Section 4 of Part A:
  - Add new customer (with details).
  - Display the new customer name on screen.

This is the Stored XSS sink — when VULNERABLE_MODE is on, the customer name
rendered on the success screen is marked |safe.

Customer search demonstrates SQLi when VULNERABLE_MODE is on.
"""
from django.conf import settings
from django.contrib import messages
from django.db import connection
from django.shortcuts import render, redirect

from accounts.auth import login_required
from customers.models import Customer, Sector, InternetPackage


@login_required
def customer_list(request):
    """List all customers + search box (search is the SQLi sink)."""
    query = request.GET.get('q', '').strip()
    customers = []

    if query:
        if settings.VULNERABLE_MODE:
            # ⚠️ VULNERABLE: SQLi via search box
            # Try: ' UNION SELECT id, username, email, password_hmac, '', '', null, null, null, null FROM accounts_user --
            with connection.cursor() as cursor:
                sql = (
                    "SELECT id, full_name, email, phone, address "
                    "FROM customers_customer "
                    f"WHERE full_name LIKE '%{query}%' OR email LIKE '%{query}%'"
                )
                try:
                    cursor.execute(sql)
                    rows = cursor.fetchall()
                    customers = [
                        {'id': r[0], 'full_name': r[1], 'email': r[2],
                         'phone': r[3], 'address': r[4]}
                        for r in rows
                    ]
                except Exception as e:
                    messages.error(request, f"Database error: {e}")
        else:
            # ✅ SECURE: ORM uses parameterized queries
            qs = Customer.objects.filter(full_name__icontains=query) | \
                 Customer.objects.filter(email__icontains=query)
            customers = list(qs.values('id', 'full_name', 'email', 'phone', 'address'))
    else:
        customers = list(
            Customer.objects.values('id', 'full_name', 'email', 'phone', 'address')
        )

    return render(request, 'customers/customer_list.html', {
        'customers': customers,
        'query': query,
    })


@login_required
def add_customer(request):
    """Add a new customer. The success screen displays the entered name —
    this is the Stored XSS sink in vulnerable mode."""
    if request.method == 'POST':
        full_name = request.POST.get('full_name', '').strip()
        email = request.POST.get('email', '').strip()
        phone = request.POST.get('phone', '').strip()
        address = request.POST.get('address', '').strip()
        sector_id = request.POST.get('sector') or None
        package_id = request.POST.get('package') or None
        notes = request.POST.get('notes', '').strip()

        if not full_name or not email:
            messages.error(request, "Name and email are required.")
            return render(request, 'customers/add_customer.html', {
                'sectors': Sector.objects.all(),
                'packages': InternetPackage.objects.all(),
            })

        if settings.VULNERABLE_MODE:
            # ⚠️ VULNERABLE: raw SQL insert with string concatenation.
            # The created_at value is injected from Python (not user input),
            # which keeps the SQLi sink in the user-controlled fields and
            # works on both PostgreSQL and SQLite.
            from django.utils.timezone import now as _now
            ts = _now().strftime('%Y-%m-%d %H:%M:%S')
            with connection.cursor() as cursor:
                sql = (
                    "INSERT INTO customers_customer "
                    "(full_name, email, phone, address, sector_id, package_id, notes, "
                    " created_at, created_by_id) "
                    f"VALUES ('{full_name}', '{email}', '{phone}', '{address}', "
                    f"{sector_id or 'NULL'}, {package_id or 'NULL'}, '{notes}', "
                    f"'{ts}', {request.current_user.id})"
                )
                try:
                    cursor.execute(sql)
                except Exception as e:
                    messages.error(request, f"Database error: {e}")
                    return render(request, 'customers/add_customer.html', {
                        'sectors': Sector.objects.all(),
                        'packages': InternetPackage.objects.all(),
                    })
        else:
            # ✅ SECURE: ORM
            Customer.objects.create(
                full_name=full_name,
                email=email,
                phone=phone,
                address=address,
                sector_id=sector_id,
                package_id=package_id,
                notes=notes,
                created_by=request.current_user,
            )

        # Display the added name on success — this is the Stored XSS sink.
        # Template renders {{ added_name|safe }} when VULNERABLE_MODE is True.
        return render(request, 'customers/customer_added.html', {
            'added_name': full_name,
        })

    return render(request, 'customers/add_customer.html', {
        'sectors': Sector.objects.all(),
        'packages': InternetPackage.objects.all(),
    })
