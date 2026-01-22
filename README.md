<div align="center">

<!-- Replace with your logo -->
<!-- <img src="docs/assets/logo.png" alt="Logo" width="120" height="120"> -->

# Canteen Management System

Backend for canteen management built with Django REST Framework.

[![Tests](https://github.com/traygo-app/canteen-management-system-server/actions/workflows/tests.yaml/badge.svg)](https://github.com/traygo-app/canteen-management-system-server/actions/workflows/tests.yaml)
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

- **Framework**: Django 5.2 + Django REST Framework
- **Database**: PostgreSQL
- **Cache**: Redis
- **Auth**: JWT
- **Payments**: Stripe
- **API Docs**: OpenAPI/Swagger

## Quick Start

### Prerequisites

- Docker
- [uv](https://docs.astral.sh/uv/getting-started/installation/) (recommended)

### First steps to run the project

1. Install `uv`, see [installation instruction](https://docs.astral.sh/uv/getting-started/installation/).
2. Clone the project
3. `cd` into the project's folder and install python requirements: ```uv sync```
4. Install pre-commit hooks: ```uv run pre-commit install```
5. Run ```docker compose up -w```
6. To add new dependencies ```uv add dependency_name``` & ```uv lock```

## API Documentation

Once the server is running, visit:

- Swagger UI: `http://localhost:8000/api/schema/swagger-ui/`
- ReDoc: `http://localhost:8000/api/schema/redoc/`

<div align="center">
Made with ❤️ at FAF
</div>
