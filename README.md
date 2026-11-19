<p align="center">
  <img src="https://raw.githubusercontent.com/jeanpmodev/jeanpmodev/main/assets/django-octo-security.jpg" alt="Django-Octo-SEO" width="100%" />
</p>

# django_octo_security pypi library package

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![Framework: Django](https://img.shields.io/badge/Framework-Django-darkgreen)](https://djangoproject.com)
[![Package Manager: Rye](https://img.shields.io/badge/Package_Manager-Rye-orange)](https://astral.sh)
![PyPI Version](https://img.shields.io/pypi/v/django_octo_security)
[![Latest on Django Packages](https://img.shields.io/badge/Django_Packages-django__octo__security-8c3c26.svg)](https://djangopackages.org/packages/p/django_octo_security/)
[![Tests: pytest](https://img.shields.io/badge/Tests-pytest%20passed-2ea44f.svg)](https://github.com/jeanpmodev/django_octo_security/blob/main/TESTING.md)
[![BDD: Behave](https://img.shields.io/badge/BDD-Behave%20verified-009688.svg)](https://github.com/jeanpmodev/django_octo_security/blob/main/TESTING.md)
[![Load Test: Locust](https://img.shields.io/badge/Load_Test-11ms_median_%7C_0%25_fails-blueviolet.svg)](https://github.com/jeanpmodev/django_octo_security/blob/main/performance/locust_load_report.pdf)
[![CI](https://img.shields.io/github/actions/workflow/status/jeanpmodev/django_octo_security/ci.yml?branch=main&label=CI)](https://github.com/jeanpmodev/django_octo_security/actions/workflows/ci.yml)
[![Code Style: PEP 8](https://img.shields.io/badge/code%20style-PEP%208-blue)](https://peps.python.org/pep-0008/)
[![PyPI Provenance](https://img.shields.io/badge/PyPI-With%20Provenance-blue?logo=pypi&logoColor=white)](https://pypi.org/project/django-octo-security/#provenance)
[![Snyk Vulnerabilities](https://img.shields.io/badge/Snyk%20Vulnerabilities-0%20known-brightgreen?logo=snyk&logoColor=white)](https://security.snyk.io/package/pip/django-octo-security)
[![Security Audit](https://github.com/jeanpmodev/django_octo_security/actions/workflows/security.yml/badge.svg)](https://github.com/jeanpmodev/django_octo_security/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/jeanpmodev/django_octo_security/badge)](https://scorecard.dev/viewer/?uri=github.com/jeanpmodev/django_octo_security)
[![Socket Badge](https://badge.socket.dev/pypi/package/django-octo-security/0.1.0?artifact_id=tar-gz)](https://badge.socket.dev/pypi/package/django-octo-security/0.1.0?artifact_id=tar-gz)
[![codecov](https://codecov.io/github/jeanpmodev/django_octo_security/graph/badge.svg?token=YUOBIXZE9A)](https://codecov.io/github/jeanpmodev/django_octo_security)
[![Documentation Status](https://readthedocs.org/projects/django-octo/badge/?version=latest)](https://django-octo.readthedocs.io/en/latest/security/)

**Enterprise-ready, non-intrusive Django runtime security posture and zero-dependency environment CVE audit module under the Django-Octo architecture.**

---

## Core Philosophy: Non-Intrusive Dual Access

`django-octo-security` is engineered to plug into any existing Django application **without altering your host project's native logic, templates, or root routes**:

1. **Public/Internal Posture Endpoint (`/security-audit/`):** Single-query database lookup (`CveAuditScan.objects.first()`) rendering enforced HTTP security headers and the latest environment vulnerability audit status.
2. **Native Django Admin Integration (`Security > CVE Checker`):** Automatically registers a dedicated administrative module in the left sidebar of `/admin/` with one-click environment scanning (`Run CVE Environment Audit`), querying the official **OSV.dev** vulnerability database via Python standard library (`importlib.metadata` + `urllib.request`) with **zero external runtime dependencies**.

---

<p align="center"> <img src="https://raw.githubusercontent.com/jeanpmodev/jeanpmodev/main/assets/django-octo-security-demo.png" alt="Demo Django Octo Security" width="600"> </p>

## Security & Audit Architecture

| Layer | Mechanism / Target | Engineering Purpose |
| :--- | :--- | :--- |
| **01** | **Clickjacking Shield** | Enforces `X-Frame-Options: DENY` to prevent unauthorized iframe embedding. |
| **02** | **MIME Sniffing Guard** | Enforces `X-Content-Type-Options: nosniff` against content-type confusion attacks. |
| **03** | **Referrer Isolation** | Applies `Referrer-Policy: strict-origin-when-cross-origin` to prevent token leakage. |
| **04** | **Single-Query Posture View** | Renders `/security-audit/` in a single ORM query for high-throughput scalability. |
| **05** | **Runtime Introspection** | Reads active virtual environment packages via native `importlib.metadata`. |
| **06** | **Batch OSV Vulnerability Query** | Cross-references all installed PyPI packages against `api.osv.dev/v1/querybatch`. |
| **07** | **Advisory Enrichment & Fixes** | Resolves CVE aliases, patched versions, and official references per vulnerability. |
| **08** | **Immutable Audit Persistence** | Stores historical snapshots (`CveAuditScan`) directly in the host database. |

---

## Plug-and-Play Installation

Install the official package directly into any modern Django (`>=6.1.2`) and Python (`>=3.12`) infrastructure using **pip** or **Rye**:

### 1. Clone & Synchronize Environment
Clone the repository and trigger the Rust-backed Rye environment compiler to lock and synchronize dependencies:
```bash
git clone https://github.com/jeanpmodev/django_octo_security.git
cd django_octo_security
rye sync
```


### 2. Register in `settings.py`
Add `"django_octo_security"` to your `INSTALLED_APPS`:
```python
INSTALLED_APPS = [
    # ... your existing apps
    "django_octo_security",
]
```

### 3. Include the Audit Route in `urls.py`
Including the module at the root preserves your host application's homepage (`/`) and mounts the posture report at `/security-audit/`:
```python
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("django_octo_security.urls")),
]
```

### 4. Apply Migrations
```bash
python3 manage.py migrate
```


### 5. Initialize Runtime Service
Fire up the local development engine instance:
```bash
python3 manage.py runserver
```
Navigate to `127.0.0.1:8000/security-audit/` to inspect live.

---

## Usage

* **Security Posture Screen:** Navigate to `http://127.0.0.1:8000/security-audit/` to inspect active HTTP security policies and the latest environment CVE audit badge.
* **Admin CVE Checker:** Log in to `http://127.0.0.1:8000/admin/`, open **Security > CVE Checker** in the left navigation bar, and click **Run CVE Environment Audit** at the top right to scan all installed Python packages in real time.

---


## Quality Assurance & Testing

This module is backed by a dedicated QA suite covering **Unit & Query-Count Tests (`pytest`)**, **BDD Specifications (`behave`)**, and **Load Testing (`locust`)**. To keep the core package minimal, test dependencies are installed on demand—see [TESTING.md](TESTING.md) for instructions and benchmark reports.


## 📄 License & Ecosystem Blueprint

Distributed under the permissive terms of the **MIT License**. 

