# Comunication_LTD — Cybersecurity Final Project (BETA)

A Django + PostgreSQL web system for a fictional communication company,
built to demonstrate **secure development principles** (Part A) and
**XSS / SQL-injection attacks and mitigations** (Part B).

---

## Two-version submission

The assignment requires two submissions: one with vulnerable code, one without.
Rather than maintaining two separate codebases, this beta uses a single flag in
`settings.py` (`VULNERABLE_MODE`) that switches the relevant code paths.

For final submission:
1. Run with `VULNERABLE_MODE=1` → record evidence of the attacks → zip as
   `communication_ltd_vulnerable.zip`.
2. Run with `VULNERABLE_MODE=0` → record evidence the attacks are blocked → zip
   as `communication_ltd_secure.zip`.

Or, if your instructor demands fully separate folders, copy the project twice
and hard-set the flag in each `settings.py`.

---

## Stack

| Layer    | Choice                              |
|----------|-------------------------------------|
| Backend  | Python 3 + Django 4.2+              |
| DB       | PostgreSQL (default) or SQLite      |
| Frontend | Django templates + plain HTML/CSS   |
| Auth     | Custom user with HMAC-SHA256 + Salt |

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure the database

**Option A — PostgreSQL (per spec):**

```bash
createdb communication_ltd
export DB_NAME=communication_ltd
export DB_USER=postgres
export DB_PASSWORD=postgres
export DB_HOST=localhost
export DB_PORT=5432
```

**Option B — SQLite (fast local testing only):**

```bash
export USE_SQLITE=1
```

### 3. Migrate + seed

```bash
python manage.py migrate
python seed.py            # populates 5 sectors and 5 internet packages
```

### 4. Run

```bash
# Vulnerable build (Part B vulnerable submission):
VULNERABLE_MODE=1 python manage.py runserver

# Secure build (Part B secure submission):
VULNERABLE_MODE=0 python manage.py runserver
```

Open http://127.0.0.1:8000/ — you'll be redirected to the register/login flow.

### 5. Email delivery

By default the reset-password token prints to the **server console** (Django's
`console` email backend). To send real email, set SMTP env vars — `settings.py`
auto-selects the SMTP backend when `EMAIL_HOST_USER` and `EMAIL_HOST_PASSWORD`
are both present, otherwise it falls back to console.

**Gmail SMTP (recommended for the demo):**

1. Enable **2-Step Verification** on your Google account
   (https://myaccount.google.com/security). This is required to create app
   passwords.
2. Generate an **App Password** at https://myaccount.google.com/apppasswords
   (choose "Mail" / "Other"). Google shows it as 4 groups of 4 characters
   separated by spaces.
3. Copy `.env.example` to `.env` and fill in:

   ```ini
   EMAIL_HOST_USER=you@gmail.com
   EMAIL_HOST_PASSWORD="xxxx xxxx xxxx xxxx"   # 16-char app password — quote it!
   DEFAULT_FROM_EMAIL=you@gmail.com
   ```

   ⚠ The quotes around `EMAIL_HOST_PASSWORD` are required because the value
   contains spaces — without them, `source .env` parses the rest of the password
   as separate shell commands.

4. Load `.env` and run:

   ```bash
   set -a; source .env; set +a
   python manage.py runserver
   ```

Gmail will rewrite the `From:` header to the authenticated `EMAIL_HOST_USER`
regardless of `DEFAULT_FROM_EMAIL` — this is anti-spoofing behavior, not a bug.

**Other SMTP providers:** override defaults via env vars
`EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_USE_TLS` / `EMAIL_USE_SSL`,
`EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`.

`.env` is in `.gitignore`; never commit credentials.

---

## Password policy (`config.json`)

The administrator can edit `config.json` without touching code. Defaults:

| Setting                  | Value                                |
|--------------------------|--------------------------------------|
| `min_length`             | 10                                   |
| `require_uppercase`      | true                                 |
| `require_lowercase`      | true                                 |
| `require_digits`         | true                                 |
| `require_special`        | true                                 |
| `history_count`          | 3 (cannot reuse last 3 passwords)    |
| `dictionary_check`       | true (uses `common_passwords.txt`)   |
| `max_login_attempts`     | 3 (then 15-min lockout)              |
| `reset_token.algorithm`  | sha1 (per assignment)                |
| `hmac.algorithm`         | sha256                               |
| `hmac.salt_bytes`        | 16                                   |

---

## Part A — Implemented features

| # | Feature                                       | File(s)                                         |
|---|-----------------------------------------------|-------------------------------------------------|
| 1 | Register screen (username, email, password)   | `accounts/views.py::register_view`              |
| 1 | Password storage as HMAC + Salt               | `accounts/utils.py::hmac_password`              |
| 1 | Complex-password policy from config           | `accounts/utils.py::validate_password_policy`   |
| 2 | Change-password screen (current → new)        | `accounts/views.py::change_password_view`       |
| 2 | Password history (last 3 blocked)             | `accounts/models.py::PasswordHistory`           |
| 3 | Login screen w/ username + password check     | `accounts/views.py::login_view`                 |
| 3 | Login-attempt limiting + lockout              | `accounts/views.py::login_view`                 |
| 4 | Customer add screen ("system" screen)         | `customers/views.py::add_customer`              |
| 4 | Display new customer name on success page     | `customers/templates/.../customer_added.html`   |
| 5 | Forgot-password (SHA-1 token, email delivery) | `accounts/views.py::forgot_password_view`       |
| 5 | Reset-password screen w/ token validation     | `accounts/views.py::reset_password_view`        |

---

## Part B — Attacks and mitigations

### Section 1 — SQL injection on Register

**Vulnerable code:** `accounts/views.py::register_view` (when `VULNERABLE_MODE=1`)
builds the username-uniqueness check using string concatenation:
```python
sql = f"SELECT id, username FROM accounts_user WHERE username = '{username}' OR email = '{email}'"
```

**Mitigation (per spec — special-character encoding / parameterized queries):**
The secure path uses Django ORM (`User.objects.filter(username=username)`),
which produces a parameterized query — the username is sent to the DB driver as
a bound parameter, never concatenated into SQL.

### Section 3 — SQL injection on Login

**Vulnerable code:** `accounts/views.py::login_view` (when `VULNERABLE_MODE=1`)
builds the user lookup with string concatenation:
```python
sql = f"SELECT id, username, ... FROM accounts_user WHERE username = '{username}'"
```

**Demo payloads:**
- `admin'--` → comment out the rest, finds `admin` row
- `' OR '1'='1` → returns the first user
- `' UNION SELECT 1,2,3,4,5,6,7 --` → leak schema info

(Note: the password check still uses HMAC+Salt verification, so an attacker
needs more than the row dump to actually authenticate. But user enumeration
is itself a serious breach.)

**Mitigation:** secure path uses `User.objects.get(username=username)` — ORM-bound parameters.

### Section 4 — SQL injection on customer add + search

**Vulnerable code:** `customers/views.py::add_customer` and `customer_list`
both build SQL with string concatenation when `VULNERABLE_MODE=1`.

**Demo payload (UNION-based dump via search):**
```
' UNION SELECT id, username, email, password_hmac, password_salt FROM accounts_user --
```
This leaks the HMAC digests and salts of every registered user into the
customer-list table. (Cracking the HMAC then becomes an offline brute-force.)

**Mitigation:** secure path uses ORM with bound parameters
(`Customer.objects.create(...)` and `Customer.objects.filter(full_name__icontains=q)`).

### Section 4 — Stored XSS via customer name

**Vulnerable code:** `customers/templates/customers/customer_added.html` and
`customer_list.html` use `{{ value|safe }}` to disable Django's auto-escaping.

**Demo payload:**
```
<script>alert('XSS')</script>
```
Submit it as the customer name. The success page shows a JS alert. Because the
name is also persisted to the DB, the same payload fires for every user who
visits the customer list — that's the **stored** part.

**Mitigation (per spec — special-character encoding):** the secure path simply
removes `|safe` and lets Django's default auto-escaping HTML-encode `<`, `>`,
`"`, `'`, `&`. The `<script>` payload renders as the literal text
`&lt;script&gt;alert('XSS')&lt;/script&gt;`.

---

## Caveats and honest disclosures

You should be ready to defend these in your write-up:

1. **SHA-1 is broken.** The assignment requires SHA-1 for the reset token.
   SHA-1 has been collision-broken since 2017 (SHAttered). For a production
   system, use SHA-256 or a HMAC over a server secret. Mention this trade-off
   in your write-up — instructors usually appreciate the awareness.

2. **HMAC is not a password hash.** Proper password storage uses a slow
   adaptive KDF (Argon2id, bcrypt, scrypt, or PBKDF2 with high iterations).
   HMAC-SHA256 is fast — an attacker with the leaked digest+salt can brute-force
   weak passwords at billions of guesses per second on GPUs. The assignment
   specifies HMAC+Salt; we follow it but you should know better in real life.

3. **The vulnerable build is intentionally exploitable** — do not deploy it
   anywhere reachable by an untrusted network. Run it on `localhost` only.

4. **`SECRET_KEY` is hard-coded** in `settings.py` for ease of grading.
   In production, load it from env vars or a secret manager.

5. **CSRF protection is enabled** on all POST forms via Django's middleware
   (`{% csrf_token %}` in templates). This is in scope of "secure development"
   even though the assignment doesn't mention it.

6. **The lockout uses a per-user counter, not per-IP.** This means an attacker
   who knows valid usernames can lock legitimate users out (DoS). A real
   system pairs per-account counters with per-IP rate limits.

7. **Email defaults to a console backend.** With no env vars set, the reset
   token prints to the Django dev server's stdout. Set `EMAIL_HOST_USER` and
   `EMAIL_HOST_PASSWORD` (plus optional `EMAIL_HOST` / `EMAIL_PORT` /
   `EMAIL_USE_TLS`) and `settings.py` auto-selects the SMTP backend. See
   **Setup → step 5** for the Gmail App-Password walkthrough.

---

## Project layout

```
communication_ltd/
├── manage.py
├── seed.py                     # populates sectors + packages
├── config.json                 # password policy (admin-editable)
├── common_passwords.txt        # dictionary blocklist
├── requirements.txt
├── README.md
├── communication_ltd/
│   ├── settings.py             # has VULNERABLE_MODE flag
│   ├── urls.py
│   └── wsgi.py
├── accounts/
│   ├── models.py               # User, PasswordHistory
│   ├── views.py                # register, login, change/forgot/reset password
│   ├── urls.py
│   ├── auth.py                 # session-backed login helpers
│   ├── utils.py                # HMAC+Salt, SHA-1 token, policy validation
│   ├── context_processors.py
│   ├── migrations/
│   └── templates/accounts/
│       ├── register.html
│       ├── login.html
│       ├── change_password.html
│       ├── forgot_password.html
│       └── reset_password.html
├── customers/
│   ├── models.py               # Sector, InternetPackage, Customer
│   ├── views.py                # add + list customers
│   ├── urls.py
│   ├── migrations/
│   └── templates/customers/
│       ├── customer_list.html
│       ├── add_customer.html
│       └── customer_added.html
└── templates/
    └── base.html
```
