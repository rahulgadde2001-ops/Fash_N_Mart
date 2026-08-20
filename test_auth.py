Yes. Below is the complete updated README.md, keeping your existing content and adding the R4 work and R4 test coverage. I also corrected the project structure/tables to reflect the R4 files you now actually have.
# Platform Service

## Overview

Platform Service handles authentication and authorization for the Supply Chain Management System.

# Features

* User authentication
* User Registration
* JWT Access Token (15 minutes)
* JWT Refresh Token (7 days)
* Refresh token storage in database
* Refresh token revocation (Logout)
* Refresh token rotation and replay protection
* Protected APIs
* Role-Based Access Control (RBAC)
* Role hierarchy support
* Login rate limiting
* Failed login tracking
* Password policy validation
* BCrypt password hashing
* Database-backed users and roles
* Admin user management
* User activation/deactivation
* Role assignment and role-change history
* Per-session management
* Session revocation
* Admin force password reset
* Authentication audit logging
* Password reset flow with single-use expiring tokens

---

## Tech Stack

- FastAPI
- Python
- Pydantic
- Uvicorn
- python-jose
- passlib
- bcrypt
- SQLAlchemy
- SQLite for development
- PostgreSQL for production

---

## Project Structure

```text
app/
├── main.py
├── database.py
├── seed.py
├── routes/
│   ├── auth_routes.py
│   ├── user_routes.py
│   └── admin_routes.py
├── schemas/
│   ├── auth.py
│   ├── user.py
│   └── admin.py
├── services/
│   ├── auth_service.py
│   ├── audit_service.py
│   └── email_service.py
├── core/
│   ├── config.py
│   ├── security.py
│   ├── dependencies.py
│   └── password_validator.py
└── models/
    ├── failed_login_attempts.py
    ├── refresh_token.py
    ├── password_reset_token.py
    ├── auth_audit_logs.py
    ├── role_change_history.py
    ├── roles.py
    └── users.py

tests/
└── test_auth.py
Roles
Implemented roles:
ceo
vp_operations
procurement_manager
logistics_manager
compliance_officer
warehouse_manager
analyst
supplier
Database
Development Database
SQLite
Production Database
PostgreSQL
Current Tables
users
roles
refresh_token
failed_login_attempts
password_reset_tokens
role_change_history
auth_audit_logs
Users and roles are stored in the database.
The seeded users are provided for development and testing purposes. They are inserted into the database by seed.py; they are not maintained in an in-memory user dictionary.
API Endpoints
Register
POST /api/v1/auth/register
Registers a new user.
Example request:
{
    "email": "newregisteruser@company.com",
    "full_name": "New Register User",
    "password": "NewRegister@123"
}
The registration flow:
Checks whether the email already exists.
Validates the password against the password policy.
Hashes the password using BCrypt.
Creates the user in the database.
Creates the user without an assigned role.
The new user's role_id is initially NULL.
Therefore, a newly registered user cannot successfully log in until an authorized administrator assigns a role.
Login
POST /api/v1/auth/login
Authenticates a user using their email and password.
A user must:
Exist in the database.
Have a valid password.
Be active.
Have an assigned role.
If the user does not have a role assigned, login is rejected with:
User role is not assigned
Successful login returns:
JWT access token
JWT refresh token
Refresh Token
POST /api/v1/auth/refresh
Takes a JSON body:
{
    "refresh_token": "<your refresh token>"
}
Returns a new access token and a new refresh token.
Refresh tokens are stored in the database and checked for:
Valid token
Non-revoked status
Expiration
Refresh tokens are rotated when used.
The previous refresh token is revoked after successful rotation.
Therefore, a refresh-token replay attack is rejected.
Current User
GET /api/v1/users/me
Returns the currently authenticated user's details.
Requires:
Authorization: Bearer <access_token>
RBAC Test
GET /api/v1/admin/test
This endpoint is protected using the role hierarchy.
The endpoint requires:
ceo
vp_operations
Higher-level roles inherit permissions from lower-level roles according to the configured role hierarchy.
Role Hierarchy
Current hierarchy:
ceo
└── vp_operations
    └── procurement_manager
        └── logistics_manager
            └── warehouse_manager
Higher roles automatically inherit permissions from lower roles defined in the hierarchy.
For example:
CEO automatically has VP Operations permissions.
VP Operations automatically has Procurement Manager permissions.
Procurement Manager automatically has Logistics Manager permissions.
Logistics Manager automatically has Warehouse Manager permissions.
The require_role, require_any_role, and require_all_roles dependencies use the configured role hierarchy as applicable.
Roles outside this hierarchy, such as analyst, supplier, and compliance_officer, only receive their explicitly configured permissions.
Password Policy
Passwords must contain:
Minimum 12 characters
At least one number
At least one special character
Password validation is called during user registration.
The password is validated before it is hashed.
Example:
Registration
    ↓
validate_password()
    ↓
hash_password()
    ↓
Store hashed password
The same password validator is reused for administrator-forced password resets and the user password-reset flow.
Login Rate Limiting
Login rate limiting is database-backed.
The system tracks failed login attempts using the failed_login_attempts table.
The current limit is:
5 failed attempts within 15 minutes
Two dimensions are checked:
Per-email
Protects an individual account from credential-stuffing attacks.
Per-IP
Protects against password spraying from a single IP address across multiple accounts.
Login is rejected with HTTP 429 Too Many Requests when either limit is reached.
Unlike the earlier implementation, rate limiting is not dependent on an in-memory Python dictionary and therefore is not limited to a single Uvicorn worker.
Logout
POST /api/v1/auth/logout
Body:
{
    "refresh_token": "<refresh_token>"
}
The refresh token is marked as revoked in the database.
After logout, the revoked refresh token cannot be used to obtain a new access token.
User Permissions
GET /api/v1/auth/me/permissions
Requires:
Authorization: Bearer <access_token>
Returns the effective permissions for the logged-in user based on the user's role and the configured role hierarchy.
For example, a CEO receives:
ceo
vp_operations
procurement_manager
logistics_manager
warehouse_manager
Seeded Users
Development and testing users are provided through:
app/seed.py
The seed process creates:
The configured roles.
The seeded users.
The relationship between users and roles.
Seeded users are stored in the database.
They are used for development and automated testing.
Example seeded users include:
ceo@company.com
vpoperations@company.com
procurementmanager@company.com
logisticsmanager@company.com
warehousemanager@company.com
compliance@company.com
analyst@company.com
supplier@company.com
Seeded users have roles assigned during the seeding process, allowing the authentication and RBAC flows to be tested immediately.
R4 Features
Round 4 extends the authentication foundation with administrative user management, per-session management, role hierarchy edge-case testing, and password reset functionality.
R4-1: Admin User Management
Administrative user management is available under:
/api/v1/admin
The following operations are implemented.
List Users
GET /api/v1/admin/users
Authorized roles:
ceo
vp_operations
Returns users stored in the database.
Create User
POST /api/v1/admin/users
Example request:
{
    "email": "r4testuser@company.com",
    "full_name": "R4 Test User",
    "password": "TestUser@12345",
    "role": "analyst"
}
The administrator:
Checks whether the user already exists.
Validates the password.
Looks up the requested role.
Hashes the password.
Creates the user.
Assigns the role.
Records the initial role assignment in role-change history.
Deactivate User
PATCH /api/v1/admin/users/{user_id}/deactivate
Authorized roles:
ceo
vp_operations
A user can be deactivated by an authorized administrator.
An administrator cannot deactivate their own account.
Change User Role
PATCH /api/v1/admin/users/{user_id}/role
Example request:
{
    "role": "analyst"
}
Role changes:
Update the user's role.
Record the previous role.
Record the new role.
Record the administrator who made the change.
Create an authentication audit log.
Role Change History
GET /api/v1/admin/users/{user_id}/role-history
Returns the role-change history for a user.
Each history record contains:
History ID
User ID
Previous role
New role
User who made the change
Timestamp
Force Reset Password
POST /api/v1/admin/users/{user_id}/force-reset-password
Example request:
{
    "new_password": "NewPassword@12345"
}
The new password is validated against the password policy before hashing.
Only authorized administrators can perform this operation.
R4-2: Per-Session Management
Refresh tokens represent individual user sessions and are stored in the database.
List Active Sessions
GET /api/v1/admin/users/{user_id}/sessions
Authorized roles:
ceo
vp_operations
The endpoint returns active sessions with:
Session ID
User ID
Created timestamp
Expiration timestamp
Revocation status
Refresh tokens themselves are not exposed through the session-management API.
Multiple Login Sessions
Multiple successful logins for the same user create separate refresh-token sessions.
For example:
Login 1
    ↓
Session A

Login 2
    ↓
Session B
Session A and Session B have different refresh tokens and can be managed independently.
Revoke Session
DELETE /api/v1/admin/users/{user_id}/sessions/{session_id}
An administrator can revoke an individual session.
The refresh token associated with that session is marked as revoked.
A TOKEN_REVOKED authentication audit event is also recorded.
Example response:
{
    "message": "Session revoked successfully"
}
Revoked Session Protection
After a session is revoked:
Refresh Token
      ↓
Database lookup
      ↓
is_revoked = True
      ↓
401 Unauthorized
The revoked refresh token cannot be used to create a new access token.
R4-3: Role Hierarchy Edge Cases
Round 4 includes explicit tests for role-hierarchy boundaries.
CEO
CEO receives all lower-level permissions defined by the hierarchy.
ceo
vp_operations
procurement_manager
logistics_manager
warehouse_manager
VP Operations
VP Operations receives its own and lower-level permissions, but does not receive CEO permissions.
vp_operations
procurement_manager
logistics_manager
warehouse_manager
CEO-only permissions are not inherited upward.
Supplier
Supplier only receives its explicitly configured supplier permission and cannot access administrator endpoints.
This verifies that role hierarchy does not accidentally grant unrelated roles administrative permissions.
R4-4: Password Reset Flow
The password reset flow is implemented as:
Request Reset
     ↓
Generate secure random token
     ↓
Store token in database
     ↓
Mock email/log output
     ↓
Reset Password
     ↓
Validate token
     ↓
Validate expiration
     ↓
Validate password
     ↓
Hash password
     ↓
Mark token as used
Request Password Reset
POST /api/v1/auth/request-password-reset
The system generates a secure random password-reset token for an existing user.
The token is stored in the database with an expiration time.
A mock email service is used for development/testing.
The response does not reveal whether the supplied email exists.
Reset Password
POST /api/v1/auth/reset-password
The reset operation validates:
Token exists.
Token has not already been used.
Token has not expired.
User exists.
New password satisfies the password policy.
After successful reset:
token.used = True
The same password-reset token cannot be used again.
R4-5: Authentication Audit Logging
Authentication-sensitive actions are recorded using the audit service.
Supported audit event types include:
LOGIN_SUCCESS
LOGIN_FAILED
ROLE_CHANGED
TOKEN_REVOKED
Audit records can be accessed by authorized administrators through:
GET /api/v1/admin/audit-logs
Optional filters:
user_id
event_type
The audit log records information such as:
Event type
User ID
Email
IP address
Details
Timestamp
Authentication Flow
Seed Database
    |
    v
Roles + Seeded Users
    |
    v
Register / Login
    |
    v
Validate User
    |
    v
Validate Role
    |
    v
Generate JWT
    |
    +------------------+
    |                  |
    v                  v
Access Token       Refresh Token
    |                  |
    v                  v
Protected API      Database Storage
    |                  |
    v                  v
JWT Validation     Token Validation
    |                  |
    v                  v
RBAC / Hierarchy   Rotation / Revocation
    |
    v
User Access
Refresh Token Rotation
The refresh-token flow is:
Refresh Token A
      |
      v
Validate Token A
      |
      v
Revoke Token A
      |
      v
Generate Token B
      |
      v
Store Token B
      |
      v
Return Access Token + Token B
If an attacker attempts to replay Token A:
Token A
   ↓
Already revoked
   ↓
401 Unauthorized
This protects against refresh-token replay attacks.
Password Reset Flow
For a newly registered or existing user:
Request Password Reset
       |
       v
Generate secure token
       |
       v
Store token + expiration
       |
       v
Mock email
       |
       v
Submit reset token
       |
       v
Check token
       |
       +---- Invalid → 400
       |
       +---- Expired → 400
       |
       +---- Already used → 400
       |
       v
Validate new password
       |
       v
Hash password
       |
       v
Mark token used
       |
       v
Password changed
Newly Registered User Flow
Register
   |
   v
User created
   |
   v
role_id = NULL
   |
   v
Cannot login yet
   |
   v
Admin assigns role
   |
   v
User can login
Setup
Create virtual environment:
python -m venv .venv
Activate:
.venv\Scripts\activate
Install dependencies:
pip install -r requirements.txt
Create the environment file:
cp .env.example .env
Then set SECRET_KEY to a random value.
Generate one with:
python -c "import secrets; print(secrets.token_urlsafe(32))"
Database Initialization
Start the application:
python -m uvicorn app.main:app --reload
The application creates the database tables using:
Base.metadata.create_all(bind=engine)
To insert the development roles and seeded users:
python -m app.seed
Run the seed command after the database tables have been created.
The seed operation is designed to avoid duplicating existing roles and users.
Swagger
http://127.0.0.1:8000/docs
Testing
Run the complete test suite:
pytest -q
Or run the authentication/R4 tests:
pytest tests/test_auth.py -v
Test Coverage
The test suite covers the authentication foundation and Round 4 requirements.
Authentication Tests
Root endpoint
Successful login
Invalid password
Invalid user
Current authenticated user
Unauthorized request without token
Successful registration
Weak password rejection
Password without number rejection
Password without special character rejection
JWT Tests
Successful JWT authentication
Expired access token rejection
Tampered access token rejection
Invalid token rejection
RBAC Tests
CEO admin access
Supplier admin access rejection
CEO inherited VP permissions
CEO inherited lower-role permissions
VP Operations does not receive CEO permissions
Supplier only receives supplier permissions
Supplier cannot access admin endpoints
Rate Limiting Tests
Per-email rate limiting
Per-IP rate limiting
Five failed attempts allowed
Sixth failed attempt rejected with HTTP 429
Rate limiting one account does not incorrectly lock another account
Refresh Token Tests
Successful refresh
Refresh token validation
Access token cannot be used as refresh token
Garbage refresh token rejection
Expired refresh token rejection
Logout revokes refresh token
Revoked refresh token cannot be reused
Refresh-token rotation
Refresh-token replay attack rejection
R4-1 Admin User Management Tests
CEO can list users
VP Operations can list users
CEO can create a user
Created user receives requested role
Created user is active
CEO can deactivate another user
Non-admin cannot deactivate users
Administrator cannot deactivate their own account
Admin can force reset a user's password
Non-admin cannot force reset password
Admin can view role-change history
Non-admin cannot view role-change history
R4-2 Per-Session Management Tests
Admin can list user sessions
Multiple logins create multiple sessions
Each login receives a different refresh token
Admin can revoke an individual session
Revoked session cannot be refreshed
Non-admin cannot list user sessions
R4-3 Role Hierarchy Edge-Case Tests
CEO receives VP Operations permissions
CEO receives lower-level permissions
VP Operations receives lower-level permissions
VP Operations does not receive CEO permissions
Supplier receives supplier permission
Supplier does not receive CEO permissions
Supplier does not receive VP Operations permissions
Supplier cannot access admin user management
R4-4 Password Reset Tests
Password reset request for existing user
Password reset request does not reveal whether email exists
Secure reset token generation
Reset token expiration
Invalid reset token rejection
Used reset token rejection
Successful password reset
Password policy enforced during reset
Reset token becomes single-use after successful reset
R4-5 Audit Logging Tests
Successful login audit event
Failed login audit event
Role-change audit event
Session-revocation audit event
Admin can retrieve audit logs
Audit logs can be filtered by user
Audit logs can be filtered by event type
R4 Test Scenarios
The most important Round 4 security scenarios are:
Refresh Token Replay
Login
  ↓
Token A
  ↓
Refresh
  ↓
Token A revoked
  ↓
Token B issued
  ↓
Replay Token A
  ↓
401 Unauthorized
Session Revocation
Login
  ↓
Session created
  ↓
Admin revokes session
  ↓
Refresh token marked revoked
  ↓
Attempt refresh
  ↓
401 Unauthorized
Role Hierarchy Boundary
CEO
 ↓
VP Operations
 ↓
Procurement Manager
 ↓
Logistics Manager
 ↓
Warehouse Manager
Higher-level roles inherit lower-level permissions, but lower-level roles do not inherit higher-level permissions.
Admin Authorization
CEO / VP Operations
        ↓
   Admin APIs
        ↓
      Allowed

Supplier
   ↓
Admin APIs
   ↓
403 Forbidden
Password Reset Single Use
Reset Token
    ↓
First use
    ↓
Password changed
    ↓
Token marked used
    ↓
Second use
    ↓
400 Bad Request
Security Summary
The Platform Service currently provides:
Database-backed authentication
BCrypt password hashing
Password policy enforcement
Short-lived JWT access tokens
Long-lived refresh tokens
Refresh-token database storage
Refresh-token rotation
Refresh-token replay protection
Refresh-token revocation
Database-backed login rate limiting
Per-email rate limiting
Per-IP rate limiting
Failed-login tracking
Role-based access control
Role hierarchy
Administrative user management
User activation/deactivation
Role-change history
Per-session management
Individual session revocation
Administrator password reset
Secure password reset tokens
Single-use password reset tokens
Expiring password reset tokens
Authentication audit logging
Automated authentication and authorization tests
Automated Round 4 security tests

This version keeps your existing README content but adds the **R4-1 through R4-5 functionality**, including the session management, refresh-token replay protection, role-hierarchy edge cases, password reset, audit logging, and the corresponding test coverage.

from datetime import timedelta
from fastapi.testclient import TestClient
from app.main import app
from app.seed import seed_database
from app.models.failed_login_attempts import FailedLoginAttempt
from app.core.security import create_access_token
from app.database import SessionLocal
client = TestClient(app)

if __name__ == "__main__":
  seed_database()
# ============================================================
# TEST HELPERS
# ============================================================

def clear_failed_login_attempts():
    
    db =SessionLocal()

    try:
        db.query(FailedLoginAttempt).delete()
        db.commit()
    finally:
        db.close()


def login_as_ceo():
    return client.post(
        "/api/v1/auth/login",
        data={
            "username": "ceo@company.com",
            "password": "ceocompany@123",
        },
    )

# ============================================================
# ROOT
# ============================================================

def test_root():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Platform Service is running"
    }

# ============================================================
# LOGIN
# ============================================================

def test_login_success():
    clear_failed_login_attempts()

    response = login_as_ceo()

    assert response.status_code == 200

    body = response.json()

    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"


def test_invalid_password():
    clear_failed_login_attempts()

    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "ceo@company.com",
            "password": "wrongpassword",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

def test_invalid_user():
    clear_failed_login_attempts()

    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "unknown@company.com",
            "password": "password123",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

# ============================================================
# CURRENT USER
# ============================================================

def test_current_user():
    clear_failed_login_attempts()

    login = login_as_ceo()

    assert login.status_code == 200

    token = login.json()["access_token"]

    response = client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 200
    assert response.json()["email"] == "ceo@company.com"

def test_current_user_without_token():
    response = client.get("/api/v1/users/me")

    assert response.status_code == 401


# ============================================================
# RBAC
# ============================================================

def test_admin_access_allowed():
    clear_failed_login_attempts()

    login = login_as_ceo()

    assert login.status_code == 200

    token = login.json()["access_token"]

    response = client.get(
        "/api/v1/admin/test",
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Admin access granted"


def test_admin_access_forbidden():
    clear_failed_login_attempts()

    login = client.post(
        "/api/v1/auth/login",
        data={
            "username": "supplier@company.com",
            "password": "supplier@123",
        },
    )

    assert login.status_code == 200

    token = login.json()["access_token"]

    response = client.get(
        "/api/v1/admin/test",
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Forbidden: insufficient permissions"
    )

# ============================================================
# DB-BACKED RATE LIMITING
# ============================================================

def test_login_rate_limit_per_email():

    clear_failed_login_attempts()

    for _ in range(5):
        response = client.post(
            "/api/v1/auth/login",
            data={
                "username": "ceo@company.com",
                "password": "wrongpassword",
            },
        )

        assert response.status_code == 401

    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "ceo@company.com",
            "password": "wrongpassword",
        },
    )

    assert response.status_code == 429

    assert response.json()["detail"] == (
        "Too many login attempts. "
        "Try again after 15 minutes."
    )


def test_login_rate_limit_per_ip():

    clear_failed_login_attempts()

    for index in range(5):
        response = client.post(
            "/api/v1/auth/login",
            data={
                "username": f"unknown{index}@company.com",
                "password": "wrongpassword",
            },
        )

        assert response.status_code == 401

    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "anotherunknown@company.com",
            "password": "wrongpassword",
        },
    )

    assert response.status_code == 429

    assert response.json()["detail"] == (
        "Too many login attempts. "
        "Try again after 15 minutes."
    )


# ============================================================
# PASSWORD POLICY / REGISTRATION
# ============================================================

def test_register_success():

    clear_failed_login_attempts()
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "newregisteruser@company.com",
            "full_name": "New Register User",
            "password": "NewRegister@123"
        }
    )

    assert response.status_code == 200
    assert response.json()["message"] == "User registered successfully"


def test_register_weak_password():

    clear_failed_login_attempts()

    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "weakuser@company.com",
            "full_name": "Weak User",
            "password": "weak123",
        },
    )

    assert response.status_code == 400


# ============================================================
# JWT
# ============================================================

def test_expired_token():
    clear_failed_login_attempts()

    expired_token = create_access_token(
        {
            "sub": "ceo@company.com",
            "role": "ceo",
            "user_id": 1,
        },
        expires_delta=timedelta(minutes=-1),
    )

    response = client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {expired_token}"
        },
    )

    assert response.status_code == 401


def test_tampered_token():
    clear_failed_login_attempts()

    login = login_as_ceo()

    assert login.status_code == 200

    token = login.json()["access_token"]

    tampered = (
        token[:-1]
        + ("A" if token[-1] != "A" else "B")
    )

    response = client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {tampered}"
        },
    )

    assert response.status_code == 401


# ============================================================
# REFRESH TOKEN
# ============================================================

def test_refresh_success():
    clear_failed_login_attempts()

    login = login_as_ceo()

    assert login.status_code == 200

    refresh = login.json()["refresh_token"]

    response = client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": refresh
        },
    )

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"

    new_token = response.json()["access_token"]

    me = client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": f"Bearer {new_token}"
        },
    )

    assert me.status_code == 200
    assert me.json()["email"] == "ceo@company.com"


def test_refresh_with_access_token_rejected():
    clear_failed_login_attempts()

    login = login_as_ceo()

    assert login.status_code == 200

    access = login.json()["access_token"]

    response = client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": access
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid refresh token"


def test_refresh_with_garbage_token_returns_401():
    clear_failed_login_attempts()

    response = client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": "not.a.real.token"
        },
    )

    assert response.status_code == 401


# ============================================================
# LOGOUT / REFRESH TOKEN REVOCATION
# ============================================================

def test_logout_revokes_refresh_token():
    clear_failed_login_attempts()

    login = login_as_ceo()

    assert login.status_code == 200

    refresh = login.json()["refresh_token"]

    logout = client.post(
        "/api/v1/auth/logout",
        json={
            "refresh_token": refresh
        },
    )

    assert logout.status_code == 200

    response = client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": refresh
        },
    )

    assert response.status_code == 401


# ============================================================
# ROLE HIERARCHY
# ============================================================

def test_ceo_has_vp_permissions():
    clear_failed_login_attempts()

    login = login_as_ceo()

    assert login.status_code == 200

    token = login.json()["access_token"]

    response = client.get(
        "/api/v1/auth/me/permissions",
        headers={
            "Authorization": f"Bearer {token}"
        },
    )
    assert response.status_code == 200
    permissions = response.json()["permissions"]
    assert "vp_operations" in permissions



