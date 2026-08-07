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

from pydantic import BaseModel, EmailStr


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str

    from app.core.password_validator import validate_password
from app.core.security import hash_password

def register_user(request: RegisterRequest):
    if request.email in users:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists"
        )

    # Enforce password policy
    validate_password(request.password)

    hashed_password = hash_password(request.password)

    users[request.email] = {
        "user_id": len(users) + 1,
        "email": request.email,
        "password": hashed_password,
        "full_name": request.full_name,
        "role": None,          # assign according to your project
        "is_active": True,
    }

    return {
        "message": "User registered successfully"
    }

    from app.schemas.auth import RegisterRequest
from app.services.auth_service import register_user
@router.post("/register")
def register(request: RegisterRequest):
    return register_user(request)in roues

    def test_register_success():
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "test@company.com",
            "password": "StrongPassword@123",
            "full_name": "Test User"
        }
    )

    assert response.status_code == 200

def test_register_invalid_password():
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "weak@company.com",
            "password": "abc123",
            "full_name": "Weak User"
        }
    )

    assert response.status_code == 400

    ## Password Policy

Passwords are validated before hashing.

Rules:

- Minimum 12 characters
- At least one number
- At least one special character

Password validation occurs during registration and any future password reset/change endpoints before the password is hashed using BCrypt.

    def require_role(*allowed_roles):

    def dependency(
        user=Depends(get_current_user)
    ):

        role = user["role"]
        user_role = getattr(user["role"], "value", user["role"])

        permissions = ROLE_HIERARCHY.get(
            user_role,
            {user_role}
        )

        if not any(
            role in permissions
            for role in allowed_roles
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: insufficient permissions"
            )

        return user

    return dependency
    }
