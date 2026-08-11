from sqlalchemy import Column, Integer, String
from app.database import Base


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True
    )

    description = Column(
        String(255),
        nullable=True
    )
    
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )

    full_name = Column(
        String(255),
        nullable=False
    )

    password = Column(
        String(255),
        nullable=False
    )

    role_id = Column(
        Integer,
        ForeignKey("roles.id"),
        nullable=True
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False
    )

    role = relationship(
        "Role",
        backref="users"
    )

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from app.database import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    token = Column(
        String(500),
        unique=True,
        nullable=False,
        index=True
    )

    is_revoked = Column(
        Boolean,
        default=False,
        nullable=False
    )

    created_at = Column(
        DateTime,
        nullable=False
    )

    expires_at = Column(
        DateTime,
        nullable=False
    )


from sqlalchemy import Column, DateTime, Integer, String
from datetime import datetime

from app.database import Base


class FailedLoginAttempt(Base):
    __tablename__ = "failed_login_attempts"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    email = Column(
        String(255),
        nullable=False,
        index=True
    )

    ip_address = Column(
        String(45),
        nullable=False,
        index=True
    )

    attempted_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True
    )
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)

from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from sqlalchemy.orm import Session

from app.database import get_db

from app.core.config import TRUST_PROXY

from app.core.security import (
    create_access_token,
    decode_token,
)

from app.core.dependencies import (
    get_current_user,
    ROLE_HIERARCHY,
)

from app.schemas.auth import (
    TokenResponse,
    RefreshRequest,
    AccessTokenResponse,
    LogoutRequest,
    RegisterRequest,
)

from app.services.auth_service import (
    login_user,
    register_user,
    users,
    get_refresh_token,
    revoke_refresh_token,
)


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"]
)


# ============================================================
# CLIENT IP
# ============================================================

def get_client_ip(request: Request) -> str:
    """
    Get the client's IP address.

    X-Forwarded-For is trusted only when the application
    is configured to run behind a trusted reverse proxy.
    """

    if TRUST_PROXY:
        forwarded_for = request.headers.get(
            "X-Forwarded-For"
        )

        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

    return request.client.host if request.client else "unknown"


# ============================================================
# REGISTER
# ============================================================

@router.post("/register")
def register(
    request: RegisterRequest,
    db: Session = Depends(get_db)
):
    return register_user(
        db=db,
        request=request
    )


# ============================================================
# LOGIN
# ============================================================

@router.post(
    "/login",
    response_model=TokenResponse
)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    client_ip = get_client_ip(request)

    return login_user(
        db=db,
        username=form_data.username,
        password=form_data.password,
        client_ip=client_ip
    )


# ============================================================
# REFRESH TOKEN
# ============================================================

@router.post(
    "/refresh",
    response_model=AccessTokenResponse
)
def refresh_token(
    body: RefreshRequest
):
    try:
        payload = decode_token(
            body.refresh_token
        )

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    # Make sure this is actually a refresh token
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    refresh = get_refresh_token(
        body.refresh_token
    )

    if refresh is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked refresh token"
        )

    email = payload.get("sub")

    user = users.get(email)

    if user is None or not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    access_token = create_access_token(
        {
            "sub": user["email"],
            "role": user["role"].value,
            "user_id": user["user_id"]
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# ============================================================
# CURRENT USER PERMISSIONS
# ============================================================

@router.get("/me/permissions")
def my_permissions(
    user=Depends(get_current_user)
):
    role = getattr(
        user["role"],
        "value",
        user["role"]
    )

    return {
        "role": role,
        "permissions": sorted(
            list(
                ROLE_HIERARCHY.get(
                    role,
                    {role}
                )
            )
        )
    }


# ============================================================
# LOGOUT
# ============================================================

@router.post("/logout")
def logout(
    body: LogoutRequest
):
    success = revoke_refresh_token(
        body.refresh_token
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Refresh token not found"
        )

    return {
        "message": "Logged out successfully"
    }
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
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.password_validator import validate_password
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from app.database import SessionLocal
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.models.failed_login import FailedLoginAttempt
from app.schemas.auth import RegisterRequest


MAX_ATTEMPTS = 5
WINDOW = timedelta(minutes=15)


# ============================================================
# REFRESH TOKEN
# ============================================================

def save_refresh_token(
    db: Session,
    user_id: int,
    token: str,
    expires_at: datetime
):
    refresh = RefreshToken(
        user_id=user_id,
        token=token,
        expires_at=expires_at,
    )

    db.add(refresh)
    db.commit()


def get_refresh_token(
    db: Session,
    token: str
):
    now = datetime.now(timezone.utc)

    return (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token == token,
            RefreshToken.is_revoked.is_(False),
            RefreshToken.expires_at > now,
        )
        .first()
    )


def revoke_refresh_token(
    db: Session,
    token: str
):
    refresh = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token == token
        )
        .first()
    )

    if refresh is None:
        return False

    refresh.is_revoked = True
    db.commit()

    return True


# ============================================================
# FAILED LOGIN TRACKING
# ============================================================

def log_failed_login(
    db: Session,
    email: str,
    ip_address: str
):
    db.add(
        FailedLoginAttempt(
            email=email,
            ip_address=ip_address,
            attempted_at=datetime.now(timezone.utc),
        )
    )

    db.commit()


def get_recent_attempts_by_email(
    db: Session,
    email: str
):
    cutoff = (
        datetime.now(timezone.utc)
        - WINDOW
    )

    return (
        db.query(FailedLoginAttempt)
        .filter(
            FailedLoginAttempt.email == email,
            FailedLoginAttempt.attempted_at >= cutoff,
        )
        .count()
    )


def get_recent_attempts_by_ip(
    db: Session,
    ip_address: str
):
    cutoff = (
        datetime.now(timezone.utc)
        - WINDOW
    )

    return (
        db.query(FailedLoginAttempt)
        .filter(
            FailedLoginAttempt.ip_address == ip_address,
            FailedLoginAttempt.attempted_at >= cutoff,
        )
        .count()
    )


def check_login_rate_limit(
    db: Session,
    email: str,
    client_ip: str
):
    email_attempts = get_recent_attempts_by_email(
        db=db,
        email=email,
    )

    ip_attempts = get_recent_attempts_by_ip(
        db=db,
        ip_address=client_ip,
    )

    if (
        email_attempts >= MAX_ATTEMPTS
        or ip_attempts >= MAX_ATTEMPTS
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again after 15 minutes.",
        )


# ============================================================
# REGISTER
# ============================================================

def register_user(
    db: Session,
    request: RegisterRequest
):
    existing = (
        db.query(User)
        .filter(
            User.email == request.email
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists",
        )

    # Validate before hashing
    validate_password(request.password)

    hashed_password = hash_password(
        request.password
    )

    user = User(
        email=request.email,
        full_name=request.full_name,
        password=hashed_password,
        is_active=True,

        # No default role.
        # Role is assigned later through
        # an authorized workflow.
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "User registered successfully"
    }


# ============================================================
# LOGIN
# ============================================================

def login(
    db: Session,
    username: str,
    password: str
):
    username = username.lower()

    user = (
        db.query(User)
        .filter(
            User.email == username
        )
        .first()
    )

    if user is None:
        return None

    if not verify_password(
        password,
        user.password
    ):
        return None

    return user


def login_user(
    db: Session,
    username: str,
    password: str,
    client_ip: str
):
    username = username.lower()

    # --------------------------------------------------------
    # Rate limit using durable DB records.
    #
    # Two dimensions are checked:
    # 1. Per email
    # 2. Per IP
    # --------------------------------------------------------

    check_login_rate_limit(
        db=db,
        email=username,
        client_ip=client_ip,
    )

    user = login(
        db=db,
        username=username,
        password=password,
    )

    # --------------------------------------------------------
    # Wrong username OR wrong password
    # --------------------------------------------------------

    if not user:
        log_failed_login(
            db=db,
            email=username,
            ip_address=client_ip,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # --------------------------------------------------------
    # Inactive account
    #
    # Do NOT reveal that the account exists.
    # --------------------------------------------------------

    if not user.is_active:
        log_failed_login(
            db=db,
            email=username,
            ip_address=client_ip,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # --------------------------------------------------------
    # No role assigned
    #
    # Registration does not automatically assign a role.
    # --------------------------------------------------------

    if not user.role:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User role is not assigned",
        )

    # --------------------------------------------------------
    # Access token
    # --------------------------------------------------------

    access_token = create_access_token(
        {
            "sub": user.email,
            "role": user.role,
            "user_id": user.id,
        }
    )

    # --------------------------------------------------------
    # Refresh token
    # --------------------------------------------------------

    refresh_token = create_refresh_token(
        {
            "sub": user.email,
            "user_id": user.id,
        }
    )

    refresh_expires_at = (
        datetime.now(timezone.utc)
        + timedelta(days=7)
    )

    save_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_token,
        expires_at=refresh_expires_at,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }
