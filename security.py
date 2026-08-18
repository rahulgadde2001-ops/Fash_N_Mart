from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.sql import func

from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    event_type = Column(
        String(100),
        nullable=False,
        index=True,
    )

    ip_address = Column(
        String(45),
        nullable=True,
    )

    details = Column(
        Text,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        index=True,
    )


from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


LOGIN_SUCCESS = "LOGIN_SUCCESS"
LOGIN_FAILED = "LOGIN_FAILED"
ROLE_CHANGED = "ROLE_CHANGED"
TOKEN_REVOKED = "TOKEN_REVOKED"
USER_CREATED = "USER_CREATED"
USER_DEACTIVATED = "USER_DEACTIVATED"
PASSWORD_FORCE_RESET = "PASSWORD_FORCE_RESET"


def create_audit_log(
    db: Session,
    event_type: str,
    ip_address: str | None = None,
    user_id: int | None = None,
    details: str | None = None,
) -> AuditLog:

    audit = AuditLog(
        user_id=user_id,
        event_type=event_type,
        ip_address=ip_address,
        details=details,
    )

    db.add(audit)
    db.commit()
    db.refresh(audit)

    return audit


admin.py
from datetime import datetime

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


user serv 
from sqlalchemy.orm import Session

from app.core.password_validator import validate_password
from app.core.security import hash_password
from app.models.refresh_token import RefreshToken
from app.models.role_history import RoleChangeHistory
from app.models.user import User
from app.services.audit_service import (
    PASSWORD_FORCE_RESET,
    ROLE_CHANGED,
    USER_CREATED,
    USER_DEACTIVATED,
    create_audit_log,
)


def get_users(db: Session):
    return db.query(User).all()


def get_user(db: Session, user_id: int):
    return (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )


def create_user(
    db: Session,
    email: str,
    password: str,
    role: str,
    ip_address: str | None,
):
    existing = (
        db.query(User)
        .filter(User.email == email.lower())
        .first()
    )

    if existing:
        raise ValueError("User already exists")

    validate_password(password)

    user = User(
        email=email.lower(),
        password_hash=hash_password(password),
        role=role,
        is_active=True,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    create_audit_log(
        db=db,
        event_type=USER_CREATED,
        user_id=user.id,
        ip_address=ip_address,
        details=f"User created with role {role}",
    )

    return user


def deactivate_user(
    db: Session,
    user_id: int,
    ip_address: str | None,
):
    user = get_user(db, user_id)

    if not user:
        raise ValueError("User not found")

    user.is_active = False

    # Deactivate all refresh-token sessions.
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.is_revoked.is_(False),
    ).update(
        {"is_revoked": True},
        synchronize_session=False,
    )

    db.commit()

    create_audit_log(
        db=db,
        event_type=USER_DEACTIVATED,
        user_id=user.id,
        ip_address=ip_address,
        details="User deactivated and active sessions revoked",
    )

    db.refresh(user)

    return user


def force_reset_password(
    db: Session,
    user_id: int,
    new_password: str,
    ip_address: str | None,
):
    user = get_user(db, user_id)

    if not user:
        raise ValueError("User not found")

    validate_password(new_password)

    user.password_hash = hash_password(new_password)

    # Force-reset should invalidate existing sessions.
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.is_revoked.is_(False),
    ).update(
        {"is_revoked": True},
        synchronize_session=False,
    )

    db.commit()

    create_audit_log(
        db=db,
        event_type=PASSWORD_FORCE_RESET,
        user_id=user.id,
        ip_address=ip_address,
        details="Password force-reset by administrator",
    )

    return user


def change_user_role(
    db: Session,
    user_id: int,
    new_role: str,
    changed_by: int,
    ip_address: str | None,
):
    user = get_user(db, user_id)

    if not user:
        raise ValueError("User not found")

    old_role = user.role

    if old_role == new_role:
        raise ValueError("User already has this role")

    user.role = new_role

    history = RoleChangeHistory(
        user_id=user.id,
        old_role=old_role,
        new_role=new_role,
        changed_by=changed_by,
        ip_address=ip_address,
    )

    db.add(history)
    db.commit()
    db.refresh(user)

    create_audit_log(
        db=db,
        event_type=ROLE_CHANGED,
        user_id=user.id,
        ip_address=ip_address,
        details=(
            f"Role changed from {old_role} "
            f"to {new_role} by user {changed_by}"
        ),
    )

    return user

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

    query = db.query(AuditLog)

    if user_id is not None:
        query = query.filter(
            AuditLog.user_id == user_id
        )

    if event_type is not None:
        query = query.filter(
            AuditLog.event_type == event_type
        )

    return (
        query
        .order_by(AuditLog.created_at.desc())
        .limit(500)
        .all()
    )
