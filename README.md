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

## API Endpoints

### Authentication
- `POST /register` - Register new user
- `POST /login` - Login and get JWT token

### User Management
- `GET /me` - Get current user profile
- `PUT /me` - Update current user profile
- `DELETE /me` - Delete current user account
- `GET /users` - Admin: List all users

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

## Dependencies

- fastapi
- sqlalchemy
- passlib[bcrypt]
- python-jose[cryptography]
- pydantic