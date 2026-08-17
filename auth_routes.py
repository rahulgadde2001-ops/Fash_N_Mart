from enum import Enum

from pydantic import BaseModel, EmailStr


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
    role: Role | None = None


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


from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.sql import func

from app.database import Base


class RoleChangeHistory(Base):
    __tablename__ = "role_change_history"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    old_role = Column(
        String(50),
        nullable=True
    )

    new_role = Column(
        String(50),
        nullable=False
    )

    changed_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False
    )

    changed_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )from fastapi import FastAPI

from app.database import Base, engine

from app.routes.auth_routes import router as auth_router
from app.routes.user_routes import router as user_router
from app.routes.admin_routes import router as admin_router

from app.models.users import User
from app.models.roles import Role
from app.models.refresh_token import RefreshToken
from app.models.failed_login import FailedLoginAttempt
from app.models.role_change_history import RoleChangeHistory


app = FastAPI()


app.include_router(admin_router)
app.include_router(auth_router)
app.include_router(user_router)


Base.metadata.create_all(bind=engine)


@app.get("/")
def root():

    
    return {
        "message": "Platform Service is running"
    }
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db

from app.models.users import User
from app.models.roles import Role as RoleModel
from app.models.role_change_history import RoleChangeHistory

from app.schemas.user import (
    AdminCreateUserRequest,
    ForceResetPasswordRequest,
    RoleChangeHistoryResponse,
    RoleChangeRequest,
    UserResponse,
)

from app.core.dependencies import require_any_role
from app.core.password_validator import validate_password
from app.core.security import hash_password


router = APIRouter(
    prefix="/api/v1/admin",
    tags=["Admin"]
)


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

    # Password policy must be enforced
    # before hashing.
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

    # If the admin created the user with a role,
    # record that assignment.
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

    # Prevent an admin from accidentally
    # deactivating their own account.
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
# CHANGE / ASSIGN ROLE
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

    # Enforce the same password policy
    # before hashing.
    validate_password(request.new_password)

    user.password = hash_password(
        request.new_password
    )

    db.commit()

    return {
        "message": "Password reset successfully"
}
