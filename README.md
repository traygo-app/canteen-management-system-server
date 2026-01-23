<div align="center">

<img src="docs/assets/logo.png" alt="Logo" width="181" height="85">

# Canteen Management System

Django REST API for TrayGo canteen management system.

[![Tests](https://github.com/traygo-app/canteen-management-system-server/actions/workflows/tests.yaml/badge.svg)](https://github.com/traygo-app/canteen-management-system-server/actions/workflows/tests.yaml)
[![Deploy](https://github.com/traygo-app/canteen-management-system-server/actions/workflows/deploy.yaml/badge.svg)](https://github.com/traygo-app/canteen-management-system-server/actions/workflows/deploy.yaml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Django 5.2](https://img.shields.io/badge/django-5.2-green.svg)](https://www.djangoproject.com/)

</div>

---

## Features

- **User Management** - Role-based access control (Admin, Staff, Customer)
- **Authentication** - JWT-based auth with MFA support (TOTP/Email)
- **Menu Management** - Daily/weekly menus with categories and items
- **Order System** - Order placement and tracking
- **Wallet System** - Digital wallet with deposits, holds, and payments
- **Stripe Integration** - Online payments via Stripe Checkout
- **Microsoft OAuth** - SSO with Microsoft accounts

## Tech Stack

- **Framework**: Django 5.2.9 + Django REST Framework 3.16.1
- **Database**: PostgreSQL 16.5
- **Cache/Sessions**: Redis 7
- **Authentication**: JWT with session whitelisting
- **Payments**: Stripe
- **API Docs**: OpenAPI/Swagger (drf-spectacular)

## Quick Start

### Prerequisites

- Docker & Docker Compose
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (Python package manager)

### Setup

1. **Install uv** - See [installation guide](https://docs.astral.sh/uv/getting-started/installation/)

2. **Clone the repository**

   ```bash
   git clone https://github.com/traygo-app/canteen-management-system-server.git
   cd canteen-management-system-server
   ```

3. **Install dependencies**

   ```bash
   uv sync
   ```

4. **Set up environment**

   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Install pre-commit hooks**

   ```bash
   uv run pre-commit install
   ```

6. **Start services**

   ```bash
   docker compose up
   ```

### Development

- **Add dependencies**: `uv add package_name` then `uv lock`
- **Run tests**: `uv run pytest`
- **Access admin**: Create superuser with `docker compose exec web python manage.py createsuperuser`

## API Documentation

Once the server is running, access the interactive API documentation:

- **Swagger UI**: <http://localhost:8000/api/schema/swagger-ui/>
- **ReDoc**: <http://localhost:8000/api/schema/redoc/>
- **Health Check**: <http://localhost:8000/health>

## Project Structure

```txt
apps/
├── authentication/    # JWT auth, MFA, OAuth
├── users/            # User management & profiles
├── menus/            # Menu, categories, items
├── orders/           # Order processing
├── wallets/          # Digital wallet & transactions
├── webhooks/         # Stripe webhook handlers
└── common/           # Shared utilities & middleware
```

## Environment Variables

Key configuration options (see `.env.example` for complete list):

- `DEBUG` - Enable debug mode (development only)
- `SECRET_KEY` - Django secret key
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_HOST` - Redis server host
- `STRIPE_SECRET_KEY` - Stripe API key
- `MFA_FERNET_KEY` - MFA encryption key
- `LOG_DIR` - Log files directory

---

<div align="center">
Made with ❤️ at FAF
</div>
