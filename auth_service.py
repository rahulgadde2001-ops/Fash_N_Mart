auth serv
from datetime import datetime, timedelta, timezone
import secrets

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.services.email_service import MockEmailService
from app.core.password_validator import validate_password
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)

from app.models.users import User
from app.models.password_reset_tokens import PasswordResetToken
from app.models.refresh_token import RefreshToken
from app.models.failed_login_attempts import FailedLoginAttempt

from app.schemas.auth import RegisterRequest

from app.services.audit_service import (
    LOGIN_SUCCESS,
    LOGIN_FAILED,
    PASSWORD_RESET,
    create_audit_log,
)


MAX_ATTEMPTS = 5
WINDOW = timedelta(minutes=15)

RESET_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7


# ============================================================
# REFRESH TOKEN
# ============================================================

def save_refresh_token(
    db: Session,
    user_id: int,
    token: str,
    expires_at: datetime,
):
    refresh = RefreshToken(
        user_id=user_id,
        token=token,
        expires_at=expires_at,
        is_revoked=False,
    )

    db.add(refresh)
    
    return refresh


def get_refresh_token(
    db: Session,
    token: str,
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
    token: str,
):
    refresh = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token == token,
        )
        .first()
    )

    if refresh is None:
        return False

    if refresh.is_revoked:
        return False

    refresh.is_revoked = True

    return True


# ============================================================
# FAILED LOGIN TRACKING / RATE LIMITING
# ============================================================

def log_failed_login(
    db: Session,
    email: str,
    ip_address: str,
):
    failed_attempt = FailedLoginAttempt(
        email=email.lower(),
        ip_address=ip_address,
        attempted_at=datetime.now(timezone.utc),
    )

    db.add(failed_attempt)
    db.commit()


def get_recent_attempts_by_email(
    db: Session,
    email: str,
):
    cutoff = (
        datetime.now(timezone.utc)
        - WINDOW
    )

    return (
        db.query(FailedLoginAttempt)
        .filter(
            FailedLoginAttempt.email == email.lower(),
            FailedLoginAttempt.attempted_at >= cutoff,
        )
        .count()
    )


def get_recent_attempts_by_ip(
    db: Session,
    ip_address: str,
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
    client_ip: str,
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


def clear_failed_login_attempts(
    db: Session,
    email: str,
    ip_address: str,
):
    """
    Clear failed login attempts after a successful login.

    This prevents a previous sequence of failed attempts
    from carrying over after the user has successfully
    authenticated.
    """

    db.query(FailedLoginAttempt).filter(
        FailedLoginAttempt.email == email.lower(),
        FailedLoginAttempt.ip_address == ip_address,
    ).delete(
        synchronize_session=False,
    )

    db.commit()


# ============================================================
# REGISTER
# ============================================================

def register_user(
    db: Session,
    request: RegisterRequest,
):
    email = request.email.lower()

    existing = (
        db.query(User)
        .filter(
            User.email == email,
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists",
        )

    # Validate the plain password BEFORE hashing.
    validate_password(request.password)

    hashed_password = hash_password(
        request.password,
    )

    user = User(
        email=email,
        full_name=request.full_name,
        password=hashed_password,
        is_active=True,
        role_id=None,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "User registered successfully",
    }


# ============================================================
# LOGIN
# ============================================================

def login(
    db: Session,
    username: str,
    password: str,
):
    username = username.lower()

    user = (
        db.query(User)
        .filter(
            User.email == username,
        )
        .first()
    )

    if user is None:
        return None

    if not verify_password(
        password,
        user.password,
    ):
        return None

    return user


def login_user(
    db: Session,
    username: str,
    password: str,
    client_ip: str,
):
    username = username.lower()

    # Check rate limit BEFORE processing credentials.
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
    # Invalid username or password
    # --------------------------------------------------------

    if not user:
        log_failed_login(
            db=db,
            email=username,
            ip_address=client_ip,
        )

        create_audit_log(
            db=db,
            event_type=LOGIN_FAILED,
            email=username,
            ip_address=client_ip,
            details="Invalid credentials",
        )

        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # --------------------------------------------------------
    # Inactive user
    # --------------------------------------------------------

    if not user.is_active:
        log_failed_login(
            db=db,
            email=username,
            ip_address=client_ip,
        )

        create_audit_log(
            db=db,
            event_type=LOGIN_FAILED,
            user_id=user.id,
            email=user.email,
            ip_address=client_ip,
            details="Inactive user",
        )

        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # --------------------------------------------------------
    # Role must be assigned
    # --------------------------------------------------------

    if not user.role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User role is not assigned",
        )

    # --------------------------------------------------------
    # Access token
    # --------------------------------------------------------

    access_token = create_access_token(
        {
            "sub": user.email,
            "role": user.role.name,
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
        + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    save_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_token,
        expires_at=refresh_expires_at,
    )

    # --------------------------------------------------------
    # Successful login audit
    # --------------------------------------------------------

    create_audit_log(
        db=db,
        event_type=LOGIN_SUCCESS,
        user_id=user.id,
        email=user.email,
        ip_address=client_ip,
        details="Login successful",
    )

    db.commit()

    # --------------------------------------------------------
    # Clear previous failed login attempts
    # --------------------------------------------------------

    db.query(FailedLoginAttempt).filter(
        FailedLoginAttempt.email == username,
        FailedLoginAttempt.ip_address == client_ip,
    ).delete(
        synchronize_session=False,
    )

    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


# ============================================================
# PASSWORD RESET - REQUEST
# ============================================================

def request_password_reset(
    db: Session,
    email: str,
):
    email = email.lower()

    user = (
        db.query(User)
        .filter(
            User.email == email,
        )
        .first()
    )

    # Do not reveal whether the email exists.
    if user is None:
        return

    # --------------------------------------------------------
    # Invalidate all previous unused reset tokens.
    # --------------------------------------------------------

    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used.is_(False),
    ).update(
        {
            PasswordResetToken.used: True,
        },
        synchronize_session=False,
    )

    # --------------------------------------------------------
    # Generate a new secure reset token.
    # --------------------------------------------------------

    token = secrets.token_urlsafe(32)

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)
    )

    reset_token = PasswordResetToken(
        user_id=user.id,
        token=token,
        expires_at=expires_at,
        used=False,
    )

    db.add(reset_token)
    db.commit()

    # --------------------------------------------------------
    # Mock email for development/testing.
    # --------------------------------------------------------

    MockEmailService.send_password_reset_email(
    email=user.email,
    reset_token=token,
)


# ============================================================
# PASSWORD RESET - CONFIRM
# ============================================================

def reset_password(
    db: Session,
    token: str,
    new_password: str,
):
    # --------------------------------------------------------
    # Find token
    # --------------------------------------------------------

    reset_token = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token == token,
        )
        .first()
    )

    if reset_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password reset token",
        )

    # --------------------------------------------------------
    # Single-use enforcement
    # --------------------------------------------------------

    if reset_token.used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset token already used",
        )

    # --------------------------------------------------------
    # Expiration check
    # --------------------------------------------------------

    now = datetime.now(timezone.utc)

    if reset_token.expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset token expired",
        )

    # --------------------------------------------------------
    # Find user
    # --------------------------------------------------------

    user = (
        db.query(User)
        .filter(
            User.id == reset_token.user_id,
        )
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password reset token",
        )

    # --------------------------------------------------------
    # Validate new password BEFORE hashing
    # --------------------------------------------------------

    validate_password(new_password)

    # --------------------------------------------------------
    # Update password
    # --------------------------------------------------------

    user.password = hash_password(
        new_password,
    )

    # --------------------------------------------------------
    # Revoke all active refresh tokens.
    #
    # This forces existing sessions to authenticate again
    # after a password reset.
    # --------------------------------------------------------

    db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.is_revoked.is_(False),
    ).update(
        {
            RefreshToken.is_revoked: True,
        },
        synchronize_session=False,
    )

    # --------------------------------------------------------
    # Make reset token single-use
    # --------------------------------------------------------

    reset_token.used = True

    # --------------------------------------------------------
    # Audit password reset
    # --------------------------------------------------------

    create_audit_log(
        db=db,
        event_type=PASSWORD_RESET,
        user_id=user.id,
        email=user.email,
        details="Password reset completed",
    )

    db.commit()


Registration behavior: Self-registration creates the account without a role. The account must be assigned a role by an authorized administrator before the user can log in. Until a role is assigned, login returns 401 User role is not assigned.

authrotes from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.config import TRUST_PROXY
from app.core.dependencies import(
    get_current_user,
    ROLE_HIERARCHY
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.database import get_db
from app.models.refresh_token import RefreshToken
from app.models.users import User
from app.schemas.auth import (
    AccessTokenResponse,
    LogoutRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)
from app.services.audit_service import (
    TOKEN_REVOKED,
    TOKEN_ROTATED,
    create_audit_log,
)
from app.services.auth_service import (
    get_refresh_token,
    register_user,
    request_password_reset,
    reset_password,
    save_refresh_token,
    login_user,
)

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


# ============================================================
# CLIENT IP
# ============================================================

def get_client_ip(request: Request) -> str:
    """
    Return the client's IP address.

    X-Forwarded-For is trusted only when the application
    is configured to run behind a trusted proxy.
    """
    if TRUST_PROXY:
        forwarded = request.headers.get("X-Forwarded-For")

        if forwarded:
            return forwarded.split(",")[0].strip()

    return request.client.host if request.client else "unknown"


# ============================================================
# REGISTER
# ============================================================

@router.post("/register")
def register(
    request: RegisterRequest,
    db: Session = Depends(get_db),
):
    return register_user(
        db=db,
        request=request,
    )


# ============================================================
# LOGIN
# ============================================================

@router.post(
    "/login",
    response_model=TokenResponse,
)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    return login_user(
        db=db,
        username=form_data.username,
        password=form_data.password,
        client_ip=get_client_ip(request),
    )


# ============================================================
# REFRESH TOKEN
# ============================================================

@router.post(
    "/refresh",
    response_model=AccessTokenResponse,
)
def refresh_token(
    body: RefreshRequest,
    db: Session = Depends(get_db),
):
    # --------------------------------------------------------
    # Decode JWT
    # --------------------------------------------------------

    try:
        payload = decode_token(body.refresh_token)

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # --------------------------------------------------------
    # Ensure this is a refresh token
    # --------------------------------------------------------

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    # --------------------------------------------------------
    # Validate refresh token against database
    # Checks:
    #   - token exists
    #   - token is not revoked
    #   - token is not expired
    # --------------------------------------------------------

    refresh = get_refresh_token(
        db=db,
        token=body.refresh_token,
    )

    if refresh is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked refresh token",
        )

    # --------------------------------------------------------
    # Find user
    # --------------------------------------------------------

    user = (
        db.query(User)
        .filter(User.id == refresh.user_id)
        .first()
    )

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user",
        )

    if user.role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User role is not assigned",
        )

    # --------------------------------------------------------
    # Create new access token
    # --------------------------------------------------------

    new_access_token = create_access_token(
        {
            "sub": user.email,
            "user_id": user.id,
            "role": user.role.name,
        }
    )

    # --------------------------------------------------------
    # Create new refresh token
    # --------------------------------------------------------

    new_refresh_token = create_refresh_token(
        {
            "sub": user.email,
            "user_id": user.id,
        }
    )

    new_refresh_expires_at = (
        datetime.now(timezone.utc)
        + timedelta(days=7)
    )

    # --------------------------------------------------------
    # Refresh-token rotation
    #
    # Old token becomes unusable.
    # New token becomes the active refresh token.
    # --------------------------------------------------------

    refresh.is_revoked = True

    save_refresh_token(
        db=db,
        user_id=user.id,
        token=new_refresh_token,
        expires_at=new_refresh_expires_at,
    )
    db.commit()
    
    # --------------------------------------------------------
    # Audit refresh-token rotation
    # --------------------------------------------------------

    create_audit_log(
        db=db,
        event_type=TOKEN_ROTATED,
        user_id=user.id,
        email=user.email,
        details="Refresh token rotated",
    )

    db.commit()

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }


# ============================================================
# PERMISSIONS
# ============================================================

@router.get("/me/permissions")
def my_permissions(
    user=Depends(get_current_user),
):
    if user.role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User role has not been assigned",
        )

    role = user.role.name

    return {
        "role": role,
        "permissions": sorted(
            list(
                ROLE_HIERARCHY.get(
                    role,
                    {role},
                )
            )
        ),
    }


# ============================================================
# LOGOUT
# ============================================================

@router.post("/logout")
def logout(
    body: LogoutRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    refresh = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token == body.refresh_token
        )
        .first()
    )

    if refresh is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Refresh token not found",
        )
    if refresh.user_id != current_user.id:
        raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Cannot revoke another user's session",
    )

    if refresh.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token already revoked",
        )

    # Revoke only this refresh-token session.
    refresh.is_revoked = True

    create_audit_log(
        db=db,
        event_type=TOKEN_REVOKED,
        user_id=refresh.user_id,
        details="Refresh token revoked during logout",
    )

    db.commit()

    return {
        "message": "Logged out successfully",
    }


# ============================================================
# PASSWORD RESET - REQUEST
# ============================================================

@router.post("/password-reset/request")
def password_reset_request(
    payload: PasswordResetRequest,
    db: Session = Depends(get_db),
):
    request_password_reset(
        db=db,
        email=payload.email,
    )

    # Do not reveal whether the account exists.
    return {
        "message": (
            "If the account exists, "
            "a password reset token has been sent."
        )
    }


# ============================================================
# PASSWORD RESET - CONFIRM
# ============================================================

@router.post("/password-reset/reset")
def password_reset_confirm(
    payload: PasswordResetConfirm,
    db: Session = Depends(get_db),
):
    reset_password(
        db=db,
        token=payload.token,
        new_password=payload.new_password,
    )

    return {
        "message": "Password has been reset successfully.",
    }

adminroutes from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db

from app.models.users import User
from app.models.roles import Role as RoleModel
from app.models.role_change_history import RoleChangeHistory
from app.models.auth_audit_logs import AuthAuditLog
from app.models.refresh_token import RefreshToken

from app.schemas.user import (
    AdminCreateUserRequest,
    RoleChangeRequest,
    RoleChangeHistoryResponse,
    ForceResetPasswordRequest,
    UserResponse,
)
from app.schemas.admin import AuditLogResponse
from app.schemas.auth import SessionResponse

from app.services.audit_service import (
    create_audit_log,
    TOKEN_REVOKED,
    ROLE_CHANGED,
)

from app.core.dependencies import (
    require_role,
    require_any_role,
)
from app.core.password_validator import validate_password
from app.core.security import hash_password


router = APIRouter(
    prefix="/api/v1/admin",
    tags=["Admin"]
)


class AdminTestResponse(BaseModel):
    message: str
    user: UserResponse


# ============================================================
# ADMIN TEST
# ============================================================

@router.get(
    "/test",
    response_model=AdminTestResponse
)
def admin_test(
    user=Depends(
        require_role("ceo", "vp_operations")
    )
):
    return {
        "message": "Admin access granted",
        "user": {
            "user_id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role.name if user.role else None,
            "is_active": user.is_active,
        }
    }


# ============================================================
# LIST USERS
# ============================================================

@router.get(
    "/users",
    response_model=list[UserResponse]
)
def list_users(
    db: Session = Depends(get_db),
    current_user=Depends(
        require_any_role("ceo", "vp_operations")
    )
):
    users = (
        db.query(User)
        .order_by(User.id)
        .all()
    )

    return [
        {
            "user_id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role.name if user.role else None,
            "is_active": user.is_active,
        }
        for user in users
    ]


# ============================================================
# CREATE USER
# ============================================================

@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
def create_user(
    request: AdminCreateUserRequest,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_any_role("ceo", "vp_operations")
    )
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

    validate_password(request.password)

    role_id = None
    role_name = None

    if request.role is not None:
        role = (
            db.query(RoleModel)
            .filter(
                RoleModel.name == request.role.value
            )
            .first()
        )

        if role is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid role"
            )

        role_id = role.id
        role_name = role.name

    user = User(
        email=email,
        full_name=request.full_name,
        password=hash_password(request.password),
        role_id=role_id,
        is_active=True,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    if role_name is not None:
        history = RoleChangeHistory(
            user_id=user.id,
            old_role=None,
            new_role=role_name,
            changed_by=current_user.id,
        )

        db.add(history)
        db.commit()

    return {
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.name if user.role else None,
        "is_active": user.is_active,
    }


# ============================================================
# DEACTIVATE USER
# ============================================================

@router.patch(
    "/users/{user_id}/deactivate",
    response_model=UserResponse
)
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_any_role("ceo", "vp_operations")
    )
):
    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account"
        )

    user.is_active = False

    db.commit()
    db.refresh(user)

    return {
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.name if user.role else None,
        "is_active": user.is_active,
    }


# ============================================================
# ASSIGN ROLE
# ============================================================

@router.patch(
    "/users/{user_id}/role",
    response_model=UserResponse
)
def change_user_role(
    user_id: int,
    request: RoleChangeRequest,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_any_role("ceo", "vp_operations")
    )
):
    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    new_role = (
        db.query(RoleModel)
        .filter(
            RoleModel.name == request.role.value
        )
        .first()
    )

    if new_role is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role"
        )

    old_role = (
        user.role.name
        if user.role
        else None
    )

    if old_role == new_role.name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has this role"
        )

    user.role_id = new_role.id

    history = RoleChangeHistory(
        user_id=user.id,
        old_role=old_role,
        new_role=new_role.name,
        changed_by=current_user.id,
    )

    db.add(history)

    # FIX: ROLE_CHANGED must be imported from audit_service
    create_audit_log(
        db=db,
        event_type=ROLE_CHANGED,
        user_id=user.id,
        email=user.email,
        details=(
            f"Role changed from {old_role} "
            f"to {new_role.name} "
            f"by user {current_user.id}"
        ),
    )

    db.commit()
    db.refresh(user)

    return {
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.name if user.role else None,
        "is_active": user.is_active,
    }


# ============================================================
# ROLE CHANGE HISTORY
# ============================================================

@router.get(
    "/users/{user_id}/role-history",
    response_model=list[RoleChangeHistoryResponse]
)
def role_change_history(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_any_role("ceo", "vp_operations")
    )
):
    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    history = (
        db.query(RoleChangeHistory)
        .filter(
            RoleChangeHistory.user_id == user_id
        )
        .order_by(
            RoleChangeHistory.changed_at.desc()
        )
        .all()
    )

    return [
        {
            "id": item.id,
            "user_id": item.user_id,
            "old_role": item.old_role,
            "new_role": item.new_role,
            "changed_by": item.changed_by,
            "changed_at": item.changed_at.isoformat(),
        }
        for item in history
    ]


# ============================================================
# FORCE RESET PASSWORD
# ============================================================

@router.post(
    "/users/{user_id}/force-reset-password"
)
def force_reset_password(
    user_id: int,
    request: ForceResetPasswordRequest,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_any_role("ceo", "vp_operations")
    )
):
    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    validate_password(request.new_password)

    user.password = hash_password(
        request.new_password
    )

# Revoke all active sessions after force password reset
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.is_revoked.is_(False),
    ).update(
    {
            RefreshToken.is_revoked: True
    },
    synchronize_session=False,
)

    db.commit()

    return {
    "message": "Password reset successfully"
}


# ============================================================
# ACTIVE SESSIONS
# ============================================================

@router.get(
    "/users/{user_id}/sessions",
    response_model=list[SessionResponse]
)
def list_user_sessions(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_any_role("ceo", "vp_operations")
    )
):
    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    now = datetime.now(timezone.utc)

    sessions = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked.is_(False),
            RefreshToken.expires_at > now
        )
        .order_by(
            RefreshToken.created_at.desc()
        )
        .all()
    )

    return [
        {
            "id": session.id,
            "user_id": session.user_id,
            "created_at": session.created_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
            "is_revoked": session.is_revoked,
        }
        for session in sessions
    ]


# ============================================================
# REVOKE SESSION
# ============================================================

@router.delete(
    "/users/{user_id}/sessions/{session_id}"
)
def revoke_user_session(
    user_id: int,
    session_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_any_role("ceo", "vp_operations")
    )
):
    session = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.id == session_id,
            RefreshToken.user_id == user_id
        )
        .first()
    )

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )

    if session.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session already revoked"
        )

    session.is_revoked = True

    create_audit_log(
        db=db,
        event_type=TOKEN_REVOKED,
        user_id=user_id,
        details=(
            f"Session {session_id} revoked "
            f"by user {current_user.id}"
        ),
    )

    db.commit()

    return {
        "message": "Session revoked successfully"
    }


# ============================================================
# AUDIT LOGS
# ============================================================

@router.get(
    "/audit-logs",
    response_model=list[AuditLogResponse],
)
def get_audit_logs(
    user_id: int | None = Query(default=None),
    event_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user=Depends(
        require_any_role("ceo", "vp_operations")
    ),
):
    query = db.query(AuthAuditLog)

    if user_id is not None:
        query = query.filter(
            AuthAuditLog.user_id == user_id
        )

    if event_type is not None:
        query = query.filter(
            AuthAuditLog.event_type == event_type
        )

    return (
        query
        .order_by(AuthAuditLog.created_at.desc())
        .limit(500)
        .all()
    )
