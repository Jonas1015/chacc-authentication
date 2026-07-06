# Authentication Module

A ChaCC API module providing user authentication and management functionality.

## Features

- User registration and login
- JWT-based authentication
- Password hashing with bcrypt
- User profile management
- Admin user listing
- Service registration for other modules

## Development

### Environment Setup

```bash
cd plugins/authentication
python module/run_tests.py setup
```

This creates a virtual environment and installs dependencies.

### Running Tests

```bash
# With venv
python module/run_tests.py test

# Without venv
python module/run_tests.py test --no-venv
```

### Standalone Development

Run the module independently for development:

```bash
python module/run_tests.py standalone
```

The module will be available at `http://localhost:8001/auth/`

### Environment Variables

- `SECRET_KEY`: JWT secret key (use strong key in production)
- `AUTHENTICATION_ENABLE_SELF_REGISTRATION`: set to `True` or `False` to allow user to selft-register

# -----------------------------------------------------------------
# Default Admin User  (used by the official chacc-auth module only)
# -----------------------------------------------------------------
- `AUTHENTICATION_DEFAULT_ADMIN_USERNAME`: set username for automatic created account
- `AUTHENTICATION_DEFAULT_ADMIN_PASSWORD`: set password for automatic created account

# -----------------------------------------------------------------
# Staff invites (Epic C7 / REQ-1.11, REQ-1.12)
# -----------------------------------------------------------------
- `AUTHENTICATION_INVITE_EXPIRE_DAYS`: invite token validity in days (default `7`)
- `AUTHENTICATION_PUBLIC_BASE_URL`: base URL used to build the invite-accept link, e.g. `https://api.example.com` (default `http://localhost:8085`)
- `AUTHENTICATION_SMTP_HOST`: SMTP relay host. If unset, invite emails are skipped and only the token/link are returned in the API response
- `AUTHENTICATION_SMTP_PORT`: SMTP port (default `587`)
- `AUTHENTICATION_SMTP_USERNAME` / `AUTHENTICATION_SMTP_PASSWORD`: SMTP auth credentials (optional; skipped if either is unset)
- `AUTHENTICATION_SMTP_FROM_EMAIL`: sender address (default `no-reply@menuapp.local`)
- `AUTHENTICATION_SMTP_USE_TLS`: `true`/`false`, whether to call `STARTTLS` (default `true`)


## API Endpoints

### Authentication
- `POST /register` - Register new user
- `POST /login` - Login and get JWT token

### User Management
- `GET /me` - Get current user profile
- `PUT /me` - Update current user profile
- `DELETE /me` - Delete current user account
- `GET /users` - Admin: List all users

### Staff invites & tenant access (Epic C7)
- `POST /invites` - Invite a user to a restaurant's staff with a role (requires global admin or an existing tenant grant with `MANAGE_MENU`)
- `POST /invites/{token}/accept` - Accept an invite and create the invited user's account (no auth required)
- `DELETE /users/{uuid}/access?restaurant_uuid=...` - Instantly revoke a user's tenant access to one restaurant

## Module Structure

```
module/
├── __init__.py
├── main.py          # Module setup
├── models.py        # Database models and schemas
├── routes.py        # API endpoints
├── auth.py          # Authentication utilities
├── dev_context.py   # Development context mock
├── context_factory.py # Context provider
├── tests/
│   └── test_module.py
└── run_tests.py     # Development tools
```

## Context Access

The module uses a context factory to work in different environments:

- **Development**: Uses provided BackboneContext
- **Production**: Uses provided BackboneContext
- **Testing**: Minimal context for isolated testing

## Services Provided

- `get_current_user`: Dependency for protecting routes in other modules which you can get by calling ChaCC `async context.get_service("get_current_user")`
- `can_access_restaurant(user, restaurant) -> bool`: **synchronous** (not awaited) tenant-access check for a specific restaurant object; consumed by the `menu` plugin. Global admins (`ALL`/`MANAGE_SYSTEM`) always pass; otherwise checks for a `RestaurantAccess` grant.
- `get_accessible_restaurant_uuids(user_id) -> list[str] | None`: **async**, returns `None` for global admins (no filter needed) or the list of restaurant UUIDs the user has tenant access to.
- `grant_restaurant_access(user_id, restaurant_uuid, role_name="MENU_MANAGER") -> None`: **async**, idempotently grants a user tenant access to a restaurant (e.g. called by the `menu` plugin after a restaurant is created, so the creator isn't locked out of managing it).

## Dependencies

- fastapi
- sqlalchemy
- passlib[bcrypt]
- python-jose[cryptography]
- pydantic