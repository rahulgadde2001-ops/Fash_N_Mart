Replace `tests/conftest.py` with this:

```python
 import os

# ENVIRONMENT
 # These must be set BEFORE any `app.*` import, because
 # app/core/config.py reads os.environ at import time.

os.environ["SECRET_KEY"] = "test-secret-key"

# Use a dedicated test database so running the suite never
 # touches (or seeds, or deletes rows from) a real dev database.

os.environ["DATABASE_URL"] = "sqlite:///./test_platform.db"

try:
 from dotenv import load_dotenv
 load_dotenv()
 except ImportError:
 pass

import pytest

from app.database import Base, engine
 from app.seed import seed_database

# DATABASE SETUP

@pytest.fixture(scope="session", autouse=True)
 def setup_test_database():
 """
 Give the suite a clean, seeded database.

 Dropping first keeps the suite idempotent: tests that create
 records (e.g. test_register_success) would otherwise fail on
 the second run with "user already exists".
 """

 Base.metadata.drop_all(bind=engine)
 Base.metadata.create_all(bind=engine)

 seed_database()

 yield

 Base.metadata.drop_all(bind=engine)
 ```

Right now, `clear_failed_login_attempts()` in `test_auth.py:16` issues a `DELETE` against whatever `DATABASE_URL` happens to be pointing at, and `test_register_success` writes a real user into it. So today running `pytest` with a real dev database configured actually mutates it. `os.environ["DATABASE_URL"]` override in the conftest closes that off , suite now always runs against its own isolated `test_platform.db`.

 the env vars have to be set *before* any `app.*` import, because `app/core/config.py` reads `os.environ` at module import time nd `app/database.py` binds the engine at import too so setting things after importing `app` would be too late. And dropping before creating is what makes the suite re runnable at all so without it, `test_register_success` registers `newregisteruser@company.com` on run 1 and gets a 400 on run 2 onward.

One thing worth knowing Rahul wjich is you actually nearly had this already. `tests/test_auth.py:10-11` already contains:
 ```python
 if __name__ == "__main__":
 seed_database()
 ```
 You'd correctly identified that seeding was needed and even wrote the call for it — the `if __name__ == "__main__"` guard is just never true when pytest imports the module, so it silently never fires. So the instinct and the mechanism were both right, just gated behind a condition that never triggers under pytest. Worth deleting those two lines once the conftest fixture is in, since they'll be genuinely dead code at that point.
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String,Text
from sqlalchemy.sql import func

from app.database import Base

class AuthAuditLog(Base):
    __tablename__ = "auth_audit_logs"

    id = Column(Integer,primary_key=True,index=True)
    user_id = Column(Integer,ForeignKey("users.id"),nullable=True,index=True )
    event_type = Column(String(50),nullable=False,index=True)
    email = Column(String(255),nullable=True,index=True )
    ip_address = Column(String(100),nullable=True)
    details = Column(Text,nullable=True)
    created_at = Column(DateTime(timezone=True),server_default=func.now(),nullable=False)

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String
from app.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class FailedLoginAttempt(Base):
    __tablename__ = "failed_login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(100), nullable=False)
    attempted_at = Column(DateTime(timezone=True),default=utc_now)

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from app.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class RefreshToken(Base):
    __tablename__ = "refresh_token"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer,nullable=False, index=True)
    token = Column(String(512), unique=True, nullable=False, index=True)
    is_revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=False)

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.sql import func

from app.database import Base


class RoleChangeHistory(Base):
    __tablename__ = "role_change_history"

    id = Column(Integer,primary_key=True,index=True)
    user_id = Column(Integer,ForeignKey("users.id"),nullable=False,index=True)
    old_role = Column(String(50),nullable=True)
    new_role = Column(String(50),nullable=False)
    changed_by = Column(Integer,ForeignKey("users.id"),nullable=False)
    changed_at = Column(DateTime(timezone=True),server_default=func.now(),nullable=False)

from sqlalchemy import Column,Integer,String
from app.database import Base
from sqlalchemy.orm import relationship

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name=Column(String(50),unique=True,nullable=False,index=True)
    description=Column(String(255),nullable=True)
    users = relationship("User",back_populates="role")

from sqlalchemy import Column,ForeignKey,Boolean,Integer,String 
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.roles import Role

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255),unique=True, nullable=False, index=True)
    full_name=Column(String(255),nullable=False)
    password=Column(String(255),nullable=False)
    is_active=Column(Boolean, default=True, nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"),nullable=True)
    role = relationship("Role",back_populates="users")

adminroutes
from fastapi import APIRouter, Depends, HTTPException, status,Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timezone

from app.database import get_db

from app.models.users import User
from app.models.roles import Role as RoleModel
from app.models.role_change_history import RoleChangeHistory

from app.schemas.user import (
    AdminCreateUserRequest,
    RoleChangeRequest,
    RoleChangeHistoryResponse,
    ForceResetPasswordRequest,
    UserResponse,

)
from app.schemas.admin import AuditLogResponse
from app.services.audit_service import AuthAuditLog
from app.models.refresh_token import RefreshToken
from app.schemas.auth import SessionResponse
from app.core.dependencies import require_role,get_current_user,require_any_role
from app.core.password_validator import validate_password
from app.core.security import hash_password

router = APIRouter(
    prefix="/api/v1/admin",
    tags=["Admin"]
)

class AdminTestResponse(BaseModel):
    message:str
    user:UserResponse

@router.get(
    "/test",
    response_model=AdminTestResponse
)

def admin_test(user=Depends(require_role("ceo","vp_operations"))):
    return {
        "message": "Admin access granted",
        "user": {
            "user_id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role.name,
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
            old_role=role_name,
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
            RefreshToken.is_revoked == False,
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

    db.commit()

    return {
        "message": "Session revoked successfully"
    }


# ============================================================
# AUDIT LOGS
# ============================================================
@router.get(
    "/audit-logs",
    response_model=list[AuditLogResponse]
)
def list_audit_logs(
    db: Session = Depends(get_db),
    current_user=Depends(
        require_any_role("ceo", "vp_operations")
    )
):
    logs = (
        db.query(AuthAuditLog)
        .order_by(
            AuthAuditLog.created_at.desc()
        )
        .all()
    )

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "event_type": log.event_type,
            "email": log.email,
            "ip_address": log.ip_address,
            "details": log.details,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]



@router.get(
    "/audit-logs",
    response_model=list[AuditLogResponse],
)
def get_audit_logs(
    user_id: int | None = Query(default=None),
    event_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    ensure_admin(current_user)

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
authroute 

from fastapi import APIRouter , HTTPException,Depends, Request,status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from app.core.config import TRUST_PROXY
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.users import User
from app.services.auth_service import (
    register_user,
    login_user,
    get_refresh_token,
    revoke_refresh_token 
)
from app.schemas.auth import (
    TokenResponse,  
    RefreshRequest,
    AccessTokenResponse,
    LogoutRequest,
    RegisterRequest
   
)
from app.core.security import (
    create_access_token,
    decode_token
)
from app.core.dependencies import(
    get_current_user,
    ROLE_HIERARCHY
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
    return login_user(
        db=db,
        username=form_data.username,
        password=form_data.password,
        client_ip=get_client_ip(request)
    )

# ============================================================
# REFRESH TOKEN
# ============================================================

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

    refresh = get_refresh_token(
        db=db,
        token=body.refresh_token
    )

    if refresh is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked refresh token"
        )

    user = (
        db.query(User)
        .filter(
            User.id == refresh.user_id
        )
        .first()
    )

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user"
        )

    if user.role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user"
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

# ============================================================
# PERMISSIONS
# ============================================================
@router.get("/me/permissions")
def my_permissions(
    user=Depends(get_current_user)
):
    if user.role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User role has not been assigned"
        )

    role = user.role.name

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
    body: LogoutRequest,
    db: Session = Depends(get_db)
):
    success = revoke_refresh_token(
        db=db,
        token=body.refresh_token
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Refresh token not found"
        )

    return {
        "message": "Logged out successfully"
    }

userroutes
from fastapi import APIRouter, Depends
from app.core.dependencies import get_current_user
from app.schemas.user import UserResponse
router = APIRouter(
    prefix="/api/v1/users",
    tags=["Users"]
)
@router.get(
    "/me",
    response_model=UserResponse
)

def current_user(
        user=Depends(get_current_user),
      
):
    return {
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.name,
        "is_active": user.is_active,
    }

admin.py from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr

class AdminUserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str


class AdminUserResponse(BaseModel):
    id: int
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ForceResetPasswordRequest(BaseModel):
    new_password: str

class RoleChangeRequest(BaseModel):
    new_role: str


class SessionResponse(BaseModel):
    id: int
    user_id: int
    created_at: datetime
    expires_at: datetime
    is_revoked: bool

    model_config = ConfigDict(from_attributes=True)


class RoleHistoryResponse(BaseModel):
    id: int
    user_id: int
    old_role: str
    new_role: str
    changed_by: int
    ip_address: str | None
    changed_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogResponse(BaseModel):
    id: int
    user_id: int | None
    event_type: str
    ip_address: str | None
    details: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


 auth.py
from pydantic import BaseModel,EmailStr

class RegisterRequest(BaseModel):
    full_name:str
    email:EmailStr
    password:str

class LoginRequest(BaseModel):
    username: str
    password: str

class LogoutRequest(BaseModel):
    refresh_token: str
    
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class RefreshRequest(BaseModel):
    refresh_token: str

class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str

class SessionResponse(BaseModel):
    id: int
    user_id: int
    created_at: str
    expires_at: str
    is_revoked: bool

user.py
from pydantic import BaseModel, EmailStr
from enum import Enum

class Role(str, Enum):
    ceo = "ceo"
    vp_operations = "vp_operations"
    procurement_manager = "procurement_manager"
    logistics_manager = "logistics_manager"
    compliance_officer = "compliance_officer"
    warehouse_manager = "warehouse_manager"
    analyst = "analyst"
    supplier = "supplier"
    
class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str

class UserResponse(BaseModel):
    user_id: int
    email: EmailStr
    full_name: str
    role: Role | None
    is_active: bool

class AdminCreateUserRequest(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: Role | None 

class RoleChangeRequest(BaseModel):
    role: Role

class ForceResetPasswordRequest(BaseModel):
    new_password: str

class RoleChangeHistoryResponse(BaseModel):
    id: int
    user_id: int
    old_role: str | None
    new_role: str
    changed_by: int
    changed_at: str

'''
 create_audit_log(
            db=db,
            event_type="ROLE_CHANGED",
            user_id=user.id,
            email=user.email,
            details=(
                f"Role changed from "
                f"{old_role} to {new_role.name}"
            ),
        )
'''
auditserv
from sqlalchemy.orm import Session

from app.models.auth_audit_logs import AuthAuditLog

LOGIN_SUCCESS = "LOGIN_SUCCESS"
LOGIN_FAILED = "LOGIN_FAILED"
ROLE_CHANGED = "ROLE_CHANGED"
TOKEN_REVOKED = "TOKEN_REVOKED"

def create_audit_log(
    db: Session,
    event_type: str,
    ip_address: str | None = None,
    user_id: int | None = None,
    email: str | None = None,
    details: str | None = None,
):
    audit = AuthAuditLog(
        event_type=event_type,
        user_id=user_id,
        email=email.lower() if email else None,
        ip_address=ip_address,
        details=details,
    )

    db.add(audit)
    db.commit()

    return audit

authserv
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.services.audit_service import create_audit_log
from app.core.password_validator import validate_password
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from app.schemas.user import RoleChangeHistoryResponse
from app.models.users import User
from app.models.refresh_token import RefreshToken
from app.models.failed_login_attempts import FailedLoginAttempt
from app.schemas.auth import RegisterRequest

from app.services.audit_service import (
    LOGIN_SUCCESS,
    LOGIN_FAILED ,
    ROLE_CHANGED ,
    TOKEN_REVOKED ,
    create_audit_log,
)

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
            detail="User already exists"
        )

    #Validate password before hashing
    validate_password(request.password)
    
    hashed_password = hash_password(
        request.password
    )

    user = User(
        email=request.email,
        full_name=request.full_name,
        password=hashed_password,
        is_active=True,
        role_id=None

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

    check_login_rate_limit(
        db=db,
        email=username,
        client_ip=client_ip,
    )

    user= login(
        db=db,
        username=username,
        password=password,
    )
    create_audit_log(
    db=db,
    event_type="LOGIN_SUCCESS",
    user_id=user.id,
    email=user.email,
    ip_address=client_ip,
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

    create_audit_log(
    db=db,
    event_type="LOGIN_FAILED",
    user_id=user.id,
    email=username,
    ip_address=client_ip,
)

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

    if not user.role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User role is not assigned",
        )
    create_audit_log(
    db=db,
    event_type="ROLE_CHANGED",
    user_id=user.id,
    ip_address=client_ip
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

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base,sessionmaker

from app.core.config import DATABASE_URL

# Database Engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


from fastapi import FastAPI

from app.routes.auth_routes import router as auth_router
from app.routes.user_routes import router as user_router
from app.routes.admin_routes import router as admin_router
from app.database import Base, engine
from app.models.users import User
from app.models.roles import Role
from app.models.refresh_token import RefreshToken
from app.models.failed_login_attempts import FailedLoginAttempt
from app.models.role_change_history import RoleChangeHistory
from app.models.auth_audit_logs import AuthAuditLog

app = FastAPI()

app.include_router(admin_router)
app.include_router(auth_router)
app.include_router(user_router)

# Create tables
Base.metadata.create_all(bind=engine)

@app.get("/")
def root():
    return {
        "message": "Platform Service is running"
    }

from app.database import SessionLocal
from app.models.users import User
from app.models.roles import Role
from app.core.security import hash_password
from app.database import Base, engine

ROLES = [
    ("ceo", "Chief Executive Officer"),
    ("vp_operations", "VP Operations"),
    ("procurement_manager", "Procurement Manager"),
    ("logistics_manager", "Logistics Manager"),
    ("compliance_officer", "Compliance Officer"),
    ("warehouse_manager", "Warehouse Manager"),
    ("analyst", "Analyst"),
    ("supplier", "Supplier"),
]

USERS = [
    {
        "email": "ceo@company.com",
        "full_name": "Company CEO",
        "password": "ceocompany@123",
        "role": "ceo",
    },
    {
        "email": "warehousemanager@company.com",
        "full_name": "Warehouse Manager",
        "password": "warehouse@123",
        "role": "warehouse_manager",
    },
    {
        "email": "vpoperations@company.com",
        "full_name": "VP Operations Manager",
        "password": "vpoperations@123",
        "role": "vp_operations",
    },
    {
        "email": "procurementmanager@company.com",
        "full_name": "Procurement Manager",
        "password": "procurement@123",
        "role": "procurement_manager",
    },
    {
        "email": "logisticsmanager@company.com",
        "full_name": "Logistics Manager",
        "password": "logistics@123",
        "role": "logistics_manager",
    },
    {
        "email": "compliance@company.com",
        "full_name": "Compliance Officer",
        "password": "compliance@123",
        "role": "compliance_officer",
    },
    {
        "email": "analyst@company.com",
        "full_name": "Analyst",
        "password": "analyst@1234",
        "role": "analyst",
    },
    {
        "email": "supplier@company.com",
        "full_name": "Supplier",
        "password": "supplier@123",
        "role": "supplier",
    },
]

def seed_database():
    db = SessionLocal()

    try:
        # ----------------------------------------
        # Create roles
        # ----------------------------------------

        role_map = {}

        for role_name, description in ROLES:
            role = (
                db.query(Role)
                .filter(Role.name == role_name)
                .first()
            )

            if role is None:
                role = Role(
                    name=role_name,
                    description=description,
                )

                db.add(role)
                db.flush()

            role_map[role_name] = role

        # ----------------------------------------
        # Create users
        # ----------------------------------------

        for data in USERS:
            email = data["email"].lower()

            existing_user = (
                db.query(User)
                .filter(User.email == email)
                .first()
            )

            if existing_user:
                continue

            user = User(
                email=email,
                full_name=data["full_name"],
                password=hash_password(data["password"]),
                role_id=role_map[data["role"]].id,
                is_active=True,
            )

            db.add(user)

        db.commit()

        print("Database seeded successfully.")

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)

    seed_database()

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
            "email": "newregisteruser01@company.com",
            "full_name": "New Register User",
            "password": "NewRegister@1234"
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


# ============================================================
# HELPERS
# ============================================================

def login_as(email: str, password: str):
    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": email,
            "password": password,
        },
    )

    assert response.status_code == 200

    return response.json()


def auth_header(token: str):
    return {
        "Authorization": f"Bearer {token}"
    }


# ============================================================
# ADMIN USER MANAGEMENT
# ============================================================


def test_ceo_can_list_users():
    login = login_as(
        "ceo@company.com",
        "ceocompany@123",
    )

    token = login["access_token"]

    response = client.get(
        "/api/v1/admin/users",
        headers=auth_header(token),
    )

    assert response.status_code == 200

    body = response.json()

    assert isinstance(body, list)


def test_vp_operations_can_list_users():
    login = login_as(
        "vpoperations@company.com",
        "vpoperations@123",
    )

    token = login["access_token"]

    response = client.get(
        "/api/v1/admin/users",
        headers=auth_header(token),
    )

    assert response.status_code == 200

    assert isinstance(response.json(), list)


def test_create_user_by_ceo():
    login = login_as(
        "ceo@company.com",
        "ceocompany@123",
    )

    token = login["access_token"]

    response = client.post(
        "/api/v1/admin/users",
        headers=auth_header(token),
        json={
            "email": "r4testuser@company.com",
            "full_name": "R4 Test User",
            "password": "TestUser@12345",
        },
    )

    assert response.status_code in (200, 201)

    body = response.json()

    assert body["email"] == "r4testuser@company.com"


def test_deactivate_user_by_ceo():
    login = login_as(
        "ceo@company.com",
        "ceocompany@123",
    )

    token = login["access_token"]

   
    response = client.patch(
        "/api/v1/admin/users/9/deactivate",
        headers=auth_header(token),
    )

    assert response.status_code in (200, 204)


def test_non_admin_cannot_deactivate_user():
    login = login_as(
        "supplier@company.com",
        "supplier@123",
    )

    token = login["access_token"]

    response = client.patch(
        "/api/v1/admin/users/9/deactivate",
        headers=auth_header(token),
    )

    assert response.status_code == 403

def test_admin_can_force_reset_password():
    login = login_as(
        "ceo@company.com",
        "ceocompany@123",
    )

    token = login["access_token"]

    response = client.post(
        "/api/v1/admin/users/9/reset-password",
        headers=auth_header(token),
        json={
            "new_password": "NewPassword@12345"
        },
    )

    assert response.status_code in (200, 204)

def test_non_admin_cannot_force_reset_password():
    login = login_as(
        "supplier@company.com",
        "supplier@123",
    )

    token = login["access_token"]

    response = client.post(
        "/api/v1/admin/users/9/reset-password",
        headers=auth_header(token),
        json={
            "new_password": "NewPassword@12345"
        },
    )

    assert response.status_code == 403

def test_admin_can_view_role_change_history():
    login = login_as(
        "ceo@company.com",
        "ceocompany@123",
    )

    token = login["access_token"]

    response = client.get(
        "/api/v1/admin/users/9/role-history",
        headers=auth_header(token),
    )

    assert response.status_code == 200

    assert isinstance(response.json(), list)


def test_non_admin_cannot_view_role_change_history():
    login = login_as(
        "supplier@company.com",
        "supplier@123",
    )

    token = login["access_token"]

    response = client.get(
        "/api/v1/admin/users/9/role-history",
        headers=auth_header(token),
    )

    assert response.status_code == 403


# ============================================================
# PER SESSION MANAGEMENT
# ============================================================


def test_user_can_list_active_sessions():
    login = login_as(
        "ceo@company.com",
        "ceocompany@123",
    )

    token = login["access_token"]

    response = client.get(
        "/api/v1/users/me/sessions",
        headers=auth_header(token),
    )

    assert response.status_code == 200

    body = response.json()

    assert isinstance(body, list)


def test_multiple_logins_create_multiple_sessions():
    login1 = login_as(
        "ceo@company.com",
        "ceocompany@123",
    )

    login2 = login_as(
        "ceo@company.com",
        "ceocompany@123",
    )

    token = login1["access_token"]

    response = client.get(
        "/api/v1/users/me/sessions",
        headers=auth_header(token),
    )

    assert response.status_code == 200

    sessions = response.json()

    assert len(sessions) >= 2


def test_user_can_revoke_specific_session():
    login1 = login_as(
        "ceo@company.com",
        "ceocompany@123",
    )

    login2 = login_as(
        "ceo@company.com",
        "ceocompany@123",
    )

    token = login1["access_token"]

    sessions_response = client.get(
        "/api/v1/users/me/sessions",
        headers=auth_header(token),
    )

    assert sessions_response.status_code == 200

    sessions = sessions_response.json()

    assert len(sessions) >= 2

    session_id = sessions[-1]["id"]

    response = client.delete(
        f"/api/v1/users/me/sessions/{session_id}",
        headers=auth_header(token),
    )

    assert response.status_code in (200, 204)


def test_revoked_session_cannot_be_refreshed():
    login = login_as(
        "ceo@company.com",
        "ceocompany@123",
    )

    access_token = login["access_token"]
    refresh_token = login["refresh_token"]

    sessions_response = client.get(
        "/api/v1/users/me/sessions",
        headers=auth_header(access_token),
    )

    assert sessions_response.status_code == 200

    sessions = sessions_response.json()

    matching_session = None

    for session in sessions:
        if session.get("token") == refresh_token:
            matching_session = session
            break

    if matching_session is not None:
        session_id = matching_session["id"]

        revoke_response = client.delete(
            f"/api/v1/users/me/sessions/{session_id}",
            headers=auth_header(access_token),
        )

        assert revoke_response.status_code in (200, 204)

        refresh_response = client.post(
            "/api/v1/auth/refresh",
            json={
                "refresh_token": refresh_token
            },
        )

        assert refresh_response.status_code == 401


def test_user_cannot_revoke_another_users_session():
    ceo_login = login_as(
        "ceo@company.com",
        "ceocompany@123",
    )

    supplier_login = login_as(
        "supplier@company.com",
        "supplier@123",
    )

    supplier_token = supplier_login["access_token"]

    response = client.get(
        "/api/v1/users/me/sessions",
        headers=auth_header(supplier_token),
    )

    assert response.status_code == 200

    sessions = response.json()

    if sessions:
        session_id = sessions[0]["id"]

        revoke_response = client.delete(
            f"/api/v1/users/me/sessions/{session_id}",
            headers=auth_header(ceo_login["access_token"]),
        )

        assert revoke_response.status_code in (403, 404)
