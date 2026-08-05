from fastapi.testclient import TestClient
from app.main import app
from app.services.auth_service import login_attempts
from app.core.security import create_access_token
from datetime import timedelta

client = TestClient(app)


def clear_attempts():
    login_attempts.clear()


def login_as_ceo():
    return client.post(
        "/api/v1/auth/login",
        data={
            "username": "ceo@company.com",
            "password": "ceocompany@123"
        }
    )


def test_root():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Platform Service is running"
    }


def test_login_success():
    clear_attempts()

    response = login_as_ceo()

    assert response.status_code == 200

    body = response.json()

    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"


def test_invalid_password():
    clear_attempts()

    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "ceo@company.com",
            "password": "wrongpassword"
        }
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_invalid_user():
    clear_attempts()

    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "unknown@company.com",
            "password": "password123"
        }
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_current_user():
    clear_attempts()

    login = login_as_ceo()

    token = login.json()["access_token"]

    response = client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200
    assert response.json()["email"] == "ceo@company.com"


def test_current_user_without_token():
    response = client.get("/api/v1/users/me")

    assert response.status_code == 401


def test_admin_access_allowed():
    clear_attempts()

    login = login_as_ceo()

    token = login.json()["access_token"]

    response = client.get(
        "/api/v1/admin/test",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Admin access granted"


def test_admin_access_forbidden():
    clear_attempts()

    login = client.post(
        "/api/v1/auth/login",
        data={
            "username": "supplier@company.com",
            "password": "supplier@123"
        }
    )

    token = login.json()["access_token"]

    response = client.get(
        "/api/v1/admin/test",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Forbidden: insufficient permissions"


def test_login_rate_limit():
    clear_attempts()

    for _ in range(5):
        client.post(
            "/api/v1/auth/login",
            data={
                "username": "ceo@company.com",
                "password": "wrongpassword"
            }
        )

    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "ceo@company.com",
            "password": "wrongpassword"
        }
    )

    assert response.status_code == 429
    assert response.json()["detail"] == "Too many login attempts. Try again after 15 minutes."


def test_expired_token():
    clear_attempts()

    expired_token = create_access_token(
        {
            "sub": "ceo@company.com",
            "role": "ceo",
            "user_id": 1
        },
        expires_delta=timedelta(minutes=-1)
    )

    response = client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {expired_token}"
        }
    )
    assert response.status_code == 401

def test_tampered_token():
    clear_attempts()

    login = login_as_ceo()

    token = login.json()["access_token"]

    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")

    response = client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {tampered}"
        }
    )
    assert response.status_code == 401

def test_refresh_success():
    clear_attempts()

    login = login_as_ceo()
    refresh = login.json()["refresh_token"]
    response = client.post(
       "/api/v1/auth/refresh",
       json={"refresh_token": refresh}
    )
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"

    new_token=response.json()["access_token"]


    me=client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {new_token}"}
    )
    assert me.status_code == 200
    assert me.json()["email"] == "ceo@company.com"

def test_refresh_with_access_token_rejected():
    clear_attempts()
    login = login_as_ceo()
    access = login.json()["access_token"]
    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": access}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid refresh token"

def test_refresh_with_garbage_token_returns_401():
    response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "not.a.real.token"}
    )
    assert response.status_code == 401

def test_rate_limit_does_not_lock_out_other_users():
    clear_attempts()
    for _ in range(5):
        client.post(
           "/api/v1/auth/login",
            data={
            "username": "ceo@company.com",
            "password": "wrongpassword"
        }
    )
    response = client.post(
    "/api/v1/auth/login",
    data={
    "username": "analyst@company.com",
    "password": "analyst@123"
    }
)
    assert response.status_code == 200


def test_logout_revokes_refresh_token():
    clear_attempts()

    login = login_as_ceo()
    refresh = login.json()["refresh_token"]

    logout = client.post(
        "/api/v1/auth/logout",
        json={
            "refresh_token": refresh
        }
    )

    assert logout.status_code == 200

    response = client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": refresh
        }
    )

    assert response.status_code == 401


def test_ceo_has_vp_permissions():
    clear_attempts()

    login = login_as_ceo()

    token = login.json()["access_token"]

    response = client.get(
        "/api/v1/auth/me/permissions",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    permissions = response.json()["permissions"]

    assert "vp_operations" in permissions

all tests


SECRET_KEY=your_secret_key

DATABASE_URL=mysql+pymysql://root:password@localhost/platform_service

TRUST_PROXY=false




from fastapi import APIRouter , HTTPException,Depends, Request,status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError

from app.core.config import TRUST_PROXY
from app.services.auth_service import (
    login_user,
    users,
    get_refresh_token,
    revoke_refresh_token 
)
from app.schemas.auth import (
    TokenResponse,
    RefreshRequest,
    AccessTokenResponse,
    LogoutRequest
)
from app.core.security import (
    create_access_token,
    decode_token,
)
from app.core.dependencies import (
    get_current_user,
    ROLE_HIERARCHY,
)

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"]
)

def get_client_ip(request: Request) -> str:
# Only trust X-Forwarded-For when we are actually behind a proxy we control.
# Otherwise any caller can forge it and reset their own rate-limit bucket.
    if TRUST_PROXY:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

@router.post(
"/login",
response_model=TokenResponse
)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    return login_user(
        username=form_data.username,
        password=form_data.password,
        client_ip=get_client_ip(request)
    )


@router.post(
"/refresh",
response_model=AccessTokenResponse
)

def refresh_token(body: RefreshRequest):
    try:
        payload = decode_token(body.refresh_token)
    except JWTError:
       raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token"
    )
    if  payload.get("type") != "refresh":
        raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token"
    )
    refresh = get_refresh_token(body.refresh_token)

    if refresh is None:
        raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or revoked refresh token"
    )

    user = users.get(payload.get("sub"))

    if user is None or not user["is_active"]:
        raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid user"
    )

    new_access_token = create_access_token(
        {
            "sub": user["email"],
            "user_id": user["user_id"],
            "role": user["role"].value
        }
)

    return {
    "access_token": new_access_token,
    "token_type": "bearer"
}

@router.get("/me/permissions")
def my_permissions(
    user=Depends(get_current_user)
):
    role = getattr(user["role"], "value", user["role"])

    return {
        "role": role,
        "permissions": sorted(
            list(
                ROLE_HIERARCHY.get(role, {role})
            )
        )
    }

@router.post("/logout")
def logout(body: LogoutRequest):

    success = revoke_refresh_token(body.refresh_token)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Refresh token not found"
        )

    return {
        "message": "Logged out successfully"
    }
# Platform Service

## Overview

Platform Service is responsible for authentication and authorization for the Supply Chain Management System.

It provides secure JWT-based authentication, refresh token management, Role-Based Access Control (RBAC), login security, and permission management.

---

# Features

* User authentication
* JWT Access Token (15 minutes)
* JWT Refresh Token (7 days)
* Refresh token storage in database
* Refresh token revocation (Logout)
* Protected APIs
* Role-Based Access Control (RBAC)
* Role hierarchy support
* Login rate limiting
* Failed login tracking
* Password policy validation
* BCrypt password hashing

---

# Tech Stack

* FastAPI
* Python
* SQLAlchemy
* SQLite (Development)
* PostgreSQL (Production)
* Pydantic
* Uvicorn
* python-jose
* passlib
* bcrypt
* pytest

---

# Project Structure

```text
app/
├── main.py
├── db/
│   └── database.py
├── routes/
│   ├── auth_routes.py
│   ├── user_routes.py
│   └── admin_routes.py
├── services/
│   └── auth_service.py
├── schemas/
│   ├── auth.py
│   └── user.py
├── core/
│   ├── config.py
│   ├── security.py
│   └── dependencies.py
└── models/
    ├── refresh_token.py
    └── failed_login.py
```

---

# Database

Development Database

* SQLite

Production Database

* PostgreSQL

Current Tables

* refresh_tokens
* failed_login_attempts

---

# Roles

Implemented Roles

* ceo
* vp_operations
* procurement_manager
* logistics_manager
* compliance_officer
* warehouse_manager
* analyst
* supplier

---

# Role Hierarchy

```
ceo
└── vp_operations
    └── procurement_manager
        └── logistics_manager
            └── warehouse_manager
```

Higher roles automatically inherit permissions from lower roles.

Example:

* CEO automatically has VP Operations permissions.
* VP Operations automatically has Procurement Manager permissions.

---

# Password Policy

Passwords must contain:

* Minimum 12 characters
* At least one uppercase letter
* At least one lowercase letter
* At least one number
* At least one special character

Passwords are securely hashed using BCrypt before storage.

---

# API Endpoints

## Login

```
POST /api/v1/auth/login
```

Returns:

* Access Token
* Refresh Token

---

## Refresh Token

```
POST /api/v1/auth/refresh
```

Body

```json
{
    "refresh_token": "<refresh_token>"
}
```

Returns a new Access Token if the Refresh Token is valid and not revoked.

---

## Logout

```
POST /api/v1/auth/logout
```

Body

```json
{
    "refresh_token": "<refresh_token>"
}
```

Revokes the refresh token from the database.

After logout, the refresh token cannot be used again.

---

## Current User

```
GET /api/v1/users/me
```

Headers

```
Authorization: Bearer <access_token>
```

Returns logged-in user information.

---

## User Permissions

```
GET /api/v1/auth/me/permissions
```

Headers

```
Authorization: Bearer <access_token>
```

Returns all effective permissions for the logged-in user based on the role hierarchy.

---

## RBAC Test

```
GET /api/v1/admin/test
```

Allowed Roles

```
ceo
vp_operations
```

---

# Authentication Flow

```
User Login
      │
      ▼
Validate Credentials
      │
      ▼
Generate Access Token (15 min)
Generate Refresh Token (7 days)
      │
      ▼
Store Refresh Token in Database
      │
      ▼
Access Protected APIs
      │
      ▼
Access Token Expires
      │
      ▼
POST /auth/refresh
      │
      ▼
Generate New Access Token
      │
      ▼
POST /auth/logout
      │
      ▼
Refresh Token Revoked
```

---

# Security Features

* BCrypt password hashing
* JWT Authentication
* Access Token expiration (15 minutes)
* Refresh Token expiration (7 days)
* Refresh Token stored in database
* Refresh Token revocation
* Login rate limiting
* Failed login tracking
* Generic authentication error messages
* Password policy validation
* Role hierarchy support

---

# Login Protection

Implemented protections:

* Maximum 5 failed login attempts
* 15-minute lockout window
* Failed login IP tracking
* Failed login timestamp logging
* Generic "Invalid credentials" response for invalid username/password

---

# Setup

## Create Virtual Environment

```bash
python -m venv .venv
```

Activate

Windows

```bash
.venv\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Create Environment File

Copy

```text
.env.example
```

to

```text
.env
```

Generate a secure secret key

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Set

```env
SECRET_KEY=<generated-secret-key>
```

---

## Run the Application

```bash
uvicorn app.main:app --reload
```

Swagger UI

```
http://127.0.0.1:8000/docs
```

---

# Testing

Implemented Tests

* Application health check
* Login success
* Invalid password
* Invalid user
* Current user endpoint
* Unauthorized access
* RBAC authorization
* Forbidden role access
* Expired JWT rejection
* Tampered JWT rejection
* Refresh token success
* Invalid refresh token type
* Malformed refresh token rejection
* Logout revokes refresh token
* Login rate limiting (5 failed attempts → 429)
* Different users have independent rate limits
* CEO inherits VP Operations permissions

---

# Current Status

Implemented

* JWT Authentication
* Access Tokens
* Refresh Tokens
* Refresh Token Database Storage
* Logout (Refresh Token Revocation)
* Role-Based Access Control (RBAC)
* Role Hierarchy
* Login Rate Limiting
* Failed Login Tracking
* Password Policy Validation
* Protected APIs
* SQLite Integration
* PostgreSQL Ready
* Unit Testing

---

# Future Enhancements

* User Registration
* Forgot Password
* Password Reset
* Email Verification
* Database-backed User Management
* OAuth Login
* API Keys for Service-to-Service Authentication
* Refresh Token Rotation
* Audit Logging
* Multi-Factor Authentication (MFA)
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String

from app.database import Base
def utc_now():
    return datetime.now(timezone.utc)

class FailedLoginAttempt(Base):
    __tablename__ = "failed_login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)
    attempted_at = Column(DateTime(timezone=True), default=utc_now)

