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

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Column, relationship

from app.database import Base


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    token = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
    )

    used = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )

    user = relationship("User")

    uthach
    class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    token: str
    new_password: str


class PasswordResetResponse(BaseModel):
    message: str
paswd seev
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.password_validator import validate_password
from app.core.security import hash_password
from app.models.password_reset_token import PasswordResetToken
from app.models.users import User
from app.services.audit_service import (
    create_audit_log,
    PASSWORD_RESET,
)


RESET_TOKEN_EXPIRE_MINUTES = 15


def request_password_reset(
    db: Session,
    email: str,
):
    email = email.lower()

    user = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    # Do not reveal whether the email exists.
    if user is None:
        return


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

    # Mock email for this round.
    print(
        f"[MOCK EMAIL] Password reset token "
        f"for {user.email}: {token}"
    )


def reset_password(
    db: Session,
    token: str,
    new_password: str,
):
    reset_token = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token == token
        )
        .first()
    )

    if reset_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password reset token",
        )

    if reset_token.used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset token already used",
        )

    now = datetime.now(timezone.utc)

    if reset_token.expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset token expired",
        )

    user = (
        db.query(User)
        .filter(User.id == reset_token.user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password reset token",
        )

    validate_password(new_password)

    user.password = hash_password(new_password)

    # Single-use enforcement.
    reset_token.used = True

    create_audit_log(
        db=db,
        event_type=PASSWORD_RESET,
        user_id=user.id,
        email=user.email,
        details="Password reset completed",
    )

    db.commit()

auth routes@router.post(
    "/password-reset/request",
    response_model=PasswordResetResponse,
)
def request_reset(
    body: PasswordResetRequest,
    db: Session = Depends(get_db),
):
    request_password_reset(
        db=db,
        email=body.email,
    )

    return {
        "message": (
            "If the email exists, "
            "a password reset token has been sent."
        )
    }

After:
user.password = hash_password(new_password)
revoke the user's existing refresh tokens:
from app.models.refresh_token import RefreshToken

db.query(RefreshToken).filter(
    RefreshToken.user_id == user.id,
    RefreshToken.is_revoked.is_(False),
).update(
    {
        RefreshToken.is_revoked: True
    },
    synchronize_session=False,
)
Then:
reset_token.used = True
This means:
password reset
      ↓
old sessions revoked
      ↓
old refresh tokens cannot create access tokens
def test_password_reset_flow():
    clear_failed_login_attempts()

    request = client.post(
        "/api/v1/auth/password-reset/request",
        json={
            "email": "ceo@company.com",
        },
    )

    assert request.status_code == 200
    def test_password_reset_token_single_use():
    client.post(
        "/api/v1/auth/password-reset/request",
        json={
            "email": "ceo@company.com",
        },
    )

    db = SessionLocal()

    try:
        reset_token = (
            db.query(PasswordResetToken)
            .order_by(
                PasswordResetToken.created_at.desc()
            )
            .first()
        )

        token = reset_token.token

    finally:
        db.close()

    first = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={
            "token": token,
            "new_password": "NewPassword@12345",
        },
    )

    assert first.status_code == 200

    second = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={
            "token": token,
            "new_password": "AnotherPassword@12345",
        },
    )

    assert second.status_code == 400
    assert (
        second.json()["detail"]
        == "Password reset token already used"
    )
    def test_password_reset_token_expired():
    from datetime import datetime, timedelta, timezone

    db = SessionLocal()

    try:
        user = (
            db.query(User)
            .filter(
                User.email == "ceo@company.com"
            )
            .first()
        )

        token = PasswordResetToken(
            user_id=user.id,
            token="expired-test-token",
            expires_at=(
                datetime.now(timezone.utc)
                - timedelta(minutes=1)
            ),
            used=False,
        )

        db.add(token)
        db.commit()

    finally:
        db.close()

    response = client.post(
        "/api/v1/auth/password-reset/confirm",
        json={
            "token": "expired-test-token",
            "new_password": "NewPassword@12345",
        },
    )

    from collections import defaultdict

from fastapi import WebSocket


class AlertConnectionManager:
    def __init__(self):
        self.connections: dict[int, list[WebSocket]] = defaultdict(list)

    async def connect(
        self,
        user_id: int,
        websocket: WebSocket,
    ):
        await websocket.accept()
        self.connections[user_id].append(websocket)

    def disconnect(
        self,
        user_id: int,
        websocket: WebSocket,
    ):
        if user_id not in self.connections:
            return

        if websocket in self.connections[user_id]:
            self.connections[user_id].remove(websocket)

        if not self.connections[user_id]:
            del self.connections[user_id]

    async def send_to_user(
        self,
        user_id: int,
        message: dict,
    ):
        connections = self.connections.get(user_id, [])

        disconnected = []

        for websocket in connections:
            try:
                await websocket.send_json(message)
            except Exception:
                disconnected.append(websocket)

        for websocket in disconnected:
            self.disconnect(user_id, websocket)


alert_manager = AlertConnectionManager()

    assert response.status_code == 400
    assert (
        response.json()["detail"]
        == "Password reset token expired"
    )
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.security import decode_token
from app.services.alert_service import alert_manager


router = APIRouter(
    prefix="/api/v1",
    tags=["Alerts"],
)


@router.websocket("/ws/alerts")
async def alerts_websocket(
    websocket: WebSocket,
):
    token = websocket.query_params.get("token")

    if not token:
        await websocket.close(code=1008)
        return

    try:
        payload = decode_token(token)

        user_id = payload.get("user_id")

        if not user_id:
            await websocket.close(code=1008)
            return

    except Exception:
        await websocket.close(code=1008)
        return

    await alert_manager.connect(
        user_id=int(user_id),
        websocket=websocket,
    )

    try:
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        alert_manager.disconnect(
            user_id=int(user_id),
            websocket=websocket,
        )
