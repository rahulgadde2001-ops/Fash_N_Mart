from fastapi import APIRouter ,Depends, Request
from fastapi.security import OAuth2PasswordRequestForm
from app.services.auth_service import login_user
from app.schemas.auth import TokenResponse
from fastapi import APIRouter, HTTPException
from app.core.security import (
    create_access_token,
    decode_token,
)

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"]
)
@router.post(
    "/login",
    response_model=TokenResponse
)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):

    client_ip = (
    request.headers.get("X-Forwarded-For", request.client.host)
    .split(",")[0]
    .strip()
)
    return login_user(
        username=form_data.username,
        password=form_data.password,
        client_ip =client_ip
)
    

@router.post("/refresh")
def refresh_token(refresh_token: str):

    payload = decode_token(refresh_token)

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )
    new_access_token = create_access_token(
        {
            "sub": payload["sub"],
            "user_id": payload["user_id"],
            "role": payload.get("role")
        }
    )
    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    token = Column(String(512), unique=True, nullable=False)

    revoked = Column(Boolean, default=False)

    expires_at = Column(DateTime, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="refresh_tokens")
    refresh_tokens = relationship(
    "RefreshToken",
    back_populates="user",
    cascade="all, delete-orphan"
    )
@router.post("/refresh")
def refresh_token(request:RefreshRequest,db:Session=Depends(get_db)):

    payload=decode_token(request.refresh_token)

    if payload["type"]!="refresh":
        raise HTTPException(401)

    token=db.query(RefreshToken).filter(
        RefreshToken.token==request.refresh_token
    ).first()

    if token is None:
        raise HTTPException(401)

    if token.revoked:
        raise HTTPException(401)

    access=create_access_token(...)

    return {"access_token":access}
    from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

from app.database import Base


class FailedLoginAttempt(Base):
    __tablename__ = "failed_login_attempts"

    id = Column(Integer, primary_key=True, index=True)

    email = Column(String(255), nullable=False, index=True)

    ip_address = Column(String(50), nullable=False)

    attempted_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )
