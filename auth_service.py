'''from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.schemas.auth import RegisterRequest

from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.models.failed_login import FailedLoginAttempt

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
            User.email == request.email.lower()
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
        role=None,
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

    return user'''

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.schemas.auth import RegisterRequest
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
        now = datetime.now(timezone.utc)

        return (
            db.query(RefreshToken)
            .filter(
                RefreshToken.token == token,
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > now
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
    window_start = (
        datetime.now(timezone.utc) - WINDOW
    )

    email_attempts = (
        db.query(FailedLoginAttempt)
        .filter(
            FailedLoginAttempt.email == email.lower(),
            FailedLoginAttempt.attempted_at >= window_start
        )
        .count()
    )

    ip_attempts = (
        db.query(FailedLoginAttempt)
        .filter(
            FailedLoginAttempt.ip_address == client_ip,
            FailedLoginAttempt.attempted_at >= window_start
        )
        .count()
    )

    if (
        email_attempts >= MAX_ATTEMPTS
        or ip_attempts >= MAX_ATTEMPTS
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again after 15 minutes."
        )


# ============================================================
# REGISTRATION
# ============================================================

def register_user(
    db: Session,
    request: RegisterRequest
):
    email = request.email.lower()

    existing = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists"
        )

    # Validate BEFORE hashing
    validate_password(request.password)

    hashed_password = hash_password(
        request.password
    )

    user = User(
        email=email,
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
    # Rate limit
    # --------------------------------------------------------

    check_login_rate_limit(
        db=db,
        email=username,
        client_ip=client_ip
    )

    # --------------------------------------------------------
    # Find user in DATABASE
    # --------------------------------------------------------

    user = (
        db.query(User)
        .filter(User.email == username)
        .first()
    )

    # --------------------------------------------------------
    # Invalid user
    # --------------------------------------------------------

    if user is None:
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
    # Invalid password
    # --------------------------------------------------------

    if not verify_password(
        password,
        user.password
    ):
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
    # --------------------------------------------------------

    if not user.is_active:
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
    # Role has not been assigned yet
    # --------------------------------------------------------

    if user.role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User role has not been assigned"
        )

    # --------------------------------------------------------
    # Create access token
    # --------------------------------------------------------

    access_token = create_access_token(
        {
            "sub": user.email,
            "role": user.role.name,
            "user_id": user.id
        }
    )

    # --------------------------------------------------------
    # Create refresh token
    # --------------------------------------------------------

    refresh_token = create_refresh_token(
        {
            "sub": user.email,
            "user_id": user.id
        }
    )

    save_refresh_token(
        user_id=user.id,
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