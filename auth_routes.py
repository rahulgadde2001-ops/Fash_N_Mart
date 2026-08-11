
from fastapi import APIRouter , HTTPException,Depends, Request,status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from app.core.config import TRUST_PROXY
from app.models.user import User
from app.services.auth_service import (
    login_user,
    get_refresh_token,
    revoke_refresh_token,
    register_user
)
from app.schemas.auth import (
    TokenResponse,
    RegisterRequest,
    AccessTokenResponse,
    RefreshRequest,
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
from sqlalchemy.orm import Session
from app.database import get_db


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
@router.post("/register")
def register(
    request: RegisterRequest,
    db: Session = Depends(get_db)
):
    return register_user(db, request)

@router.post(
    "/login",
    response_model=TokenResponse
)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    return login_user(
        db=db,
        username=form_data.username,
        password=form_data.password,
        client_ip=get_client_ip(request)
    )
@router.post(
    "/refresh",
    response_model=AccessTokenResponse
)
def refresh_token(
    body: RefreshRequest,
    db: Session = Depends(get_db)
):
    try:
        payload = decode_token(body.refresh_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    if payload.get("type") != "refresh":
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

    user = (
        db.query(User)
        .filter(User.id == payload.get("user_id"))
        .first()
    )

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user"
        )

    if user.role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User role has not been assigned"
        )

    new_access_token = create_access_token(
        {
            "sub": user.email,
            "user_id": user.id,
            "role": user.role.name
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




depen from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError

from app.core.security import decode_token
from app.services.auth_service import users

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login"
)

# Authentication
def get_current_user(
    token: str = Depends(oauth2_scheme)
):
    try:
        payload = decode_token(token)

        email = payload.get("sub")

        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

        user = users.get(email)

        if user is None or not user["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or inactive user"
            )

        return user

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )


def require_any_role(*allowed_roles):

    def dependency(user=Depends(get_current_user)):

        user_role = getattr(user["role"], "value", user["role"])

        permissions = ROLE_HIERARCHY.get(user_role, {user_role})

        if not any(role in permissions for role in allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden"
            )

        return user

    return dependency

def require_all_roles(*required_roles):

    def dependency(user=Depends(get_current_user)):

        user_role = getattr(user["role"], "value", user["role"])

        permissions = ROLE_HIERARCHY.get(user_role, {user_role})

        if not all(role in permissions for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden"
            )

        return user

    return dependency

# RBAC
def require_role(*allowed_roles):

    def dependency(
        user=Depends(get_current_user)
    ):

        role = user["role"]
        user_role = getattr(role, "value", role)

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

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.schemas.auth import RegisterRequest
from app.schemas.user import Role

from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.models.failed_login import FailedLoginAttempt

from app.database import SessionLocal

from app.core.password_validator import validate_password

from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)


MAX_ATTEMPTS = 5
WINDOW = timedelta(minutes=15)


# ============================================================
# REFRESH TOKEN
# ============================================================

def save_refresh_token(
    user_id: int,
    token: str,
    expires_at
):
    db = SessionLocal()

    try:
        refresh = RefreshToken(
            user_id=user_id,
            token=token,
            expires_at=expires_at
        )

        db.add(refresh)
        db.commit()

    finally:
        db.close()


def get_refresh_token(token: str):
    db = SessionLocal()

    try:
        return (
            db.query(RefreshToken)
            .filter(
                RefreshToken.token == token,
                RefreshToken.is_revoked == False
            )
            .first()
        )

    finally:
        db.close()


def revoke_refresh_token(token: str):
    db = SessionLocal()

    try:
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

    finally:
        db.close()


# ============================================================
# FAILED LOGIN / RATE LIMITING
# ============================================================

def log_failed_login(
    db: Session,
    email: str,
    ip_address: str
):
    db.add(
        FailedLoginAttempt(
            email=email.lower(),
            ip_address=ip_address
        )
    )

    db.commit()


def check_login_rate_limit(
    db: Session,
    email: str,
    client_ip: str
):
    """
    Protect against:

    1. Credential stuffing:
       Same email from many different IP addresses.

    2. Password spraying:
       Same IP attacking many different accounts.

    Limit:
       5 failed attempts within 15 minutes.
    """

    window_start = (
        datetime.now(timezone.utc) - WINDOW
    )

    # --------------------------------------------------------
    # Per-email limit
    # --------------------------------------------------------

    email_attempts = (
        db.query(FailedLoginAttempt)
        .filter(
            FailedLoginAttempt.email == email.lower(),
            FailedLoginAttempt.attempted_at >= window_start
        )
        .count()
    )

    # --------------------------------------------------------
    # Per-IP limit
    # --------------------------------------------------------

    ip_attempts = (
        db.query(FailedLoginAttempt)
        .filter(
            FailedLoginAttempt.ip_address == client_ip,
            FailedLoginAttempt.attempted_at >= window_start
        )
        .count()
    )

    # --------------------------------------------------------
    # Block if either limit is reached
    # --------------------------------------------------------

    if (
        email_attempts >= MAX_ATTEMPTS
        or ip_attempts >= MAX_ATTEMPTS
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Too many login attempts. "
                "Try again after 15 minutes."
            )
        )


# ============================================================
# REGISTRATION
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
            detail="User already exists"
        )

    # Validate password BEFORE hashing
    validate_password(request.password)

    hashed_password = hash_password(
        request.password
    )

    user = User(
        email=request.email,
        full_name=request.full_name,
        password=hashed_password,
        is_active=True,
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

def login_user(
    db: Session,
    username: str,
    password: str,
    client_ip: str
):
    username = username.lower()

    # --------------------------------------------------------
    # Check DB-based rate limit BEFORE authentication
    # --------------------------------------------------------

    check_login_rate_limit(
        db=db,
        email=username,
        client_ip=client_ip
    )

    # --------------------------------------------------------
    # Authenticate user
    # --------------------------------------------------------

    user = login(
        username,
        password
    )

    # --------------------------------------------------------
    # Wrong username/password
    # --------------------------------------------------------

    if not user:

        log_failed_login(
            db=db,
            email=username,
            ip_address=client_ip
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # --------------------------------------------------------
    # Inactive user
    #
    # Do NOT reveal that the account exists.
    # Return the same generic error.
    # --------------------------------------------------------

    if not user["is_active"]:

        log_failed_login(
            db=db,
            email=username,
            ip_address=client_ip
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # --------------------------------------------------------
    # Successful login
    # --------------------------------------------------------

    access_token = create_access_token(
        {
            "sub": user["email"],
            "role": user["role"].value,
            "user_id": user["user_id"]
        }
    )

    refresh_token = create_refresh_token(
        {
            "sub": user["email"],
            "user_id": user["user_id"]
        }
    )

    save_refresh_token(
        user_id=user["user_id"],
        token=refresh_token,
        expires_at=(
            datetime.now(timezone.utc)
            + timedelta(days=7)
        )
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


# ============================================================
# SEEDED USERS
# ============================================================

users = {

    "ceo@company.com": {
        "user_id": 1,
        "email": "ceo@company.com",
        "password": hash_password(
            "ceocompany@123"
        ),
        "full_name": "Company CEO",
        "role": Role.ceo,
        "is_active": True,
    },

    "warehousemanager@company.com": {
        "user_id": 2,
        "email": "warehousemanager@company.com",
        "password": hash_password(
            "warehouse@123"
        ),
        "full_name": "Warehouse Manager",
        "role": Role.warehouse_manager,
        "is_active": True,
    },

    "vpoperations@company.com": {
        "user_id": 3,
        "email": "vpoperations@company.com",
        "password": hash_password(
            "vpoperations@123"
        ),
        "full_name": "VP Operations Manager",
        "role": Role.vp_operations,
        "is_active": True,
    },

    "procurementmanager@company.com": {
        "user_id": 4,
        "email": "procurementmanager@company.com",
        "password": hash_password(
            "procurement@123"
        ),
        "full_name": "Procurement Manager",
        "role": Role.procurement_manager,
        "is_active": True,
    },

    "logisticsmanager@company.com": {
        "user_id": 5,
        "email": "logisticsmanager@company.com",
        "password": hash_password(
            "logistics@123"
        ),
        "full_name": "Logistics Manager",
        "role": Role.logistics_manager,
        "is_active": True,
    },

    "compliance@company.com": {
        "user_id": 6,
        "email": "compliance@company.com",
        "password": hash_password(
            "compliance@123"
        ),
        "full_name": "Compliance Officer",
        "role": Role.compliance_officer,
        "is_active": True,
    },

    "analyst@company.com": {
        "user_id": 7,
        "email": "analyst@company.com",
        "password": hash_password(
            "analyst@123"
        ),
        "full_name": "Analyst",
        "role": Role.analyst,
        "is_active": True,
    },

    "supplier@company.com": {
        "user_id": 8,
        "email": "supplier@company.com",
        "password": hash_password(
            "supplier@123"
        ),
        "full_name": "Supplier",
        "role": Role.supplier,
        "is_active": True,
    },
}


# ============================================================
# AUTHENTICATE SEEDED USER
# ============================================================

def login(
    username: str,
    password: str
):
    user = users.get(
        username.lower()
    )

    if user is None:
        return None

    if not verify_password(
        password,
        user["password"]
    ):
        return None

    return user
