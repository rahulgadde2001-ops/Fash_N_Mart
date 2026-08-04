
import re

def validate_password(password):

    if len(password)<12:
        return False

    if not re.search(r"\d7",password):
        return False

    if not re.search(r"[!@#$%^&*]",password):
        return False

    return True

import os

from dotenv import load_dotenv

load_dotenv()

# JWT Secret
SECRET_KEY = os.environ["SECRET_KEY"]

# Database URL
DATABASE_URL = os.environ["DATABASE_URL"]

# JWT Algorithm
ALGORITHM = "HS256"

# Access Token Expiry
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Refresh Token Expiry
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Reverse Proxy Trust
TRUST_PROXY = (
    os.getenv(
        "TRUST_PROXY",
        "false"
    ).lower() == "true"
)

SECRET_KEY=your_secret_key

DATABASE_URL=mysql+pymysql://root:password@localhost/platform_service

TRUST_PROXY=false

#db.py
"""
Database Configuration

Creates:

1. Engine
2. Session
3. Base

Every SQLAlchemy model
inherits Base.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

from app.core.config import DATABASE_URL


# Database Engine
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True
)

# Session Factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Parent of all Models
Base = declarative_base()


def get_db():
    """
    Opens DB connection.

    Automatically closes
    after request.
    """

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()

#models
"""
Refresh Token Model

Stores every refresh token.

Without this table,
logout cannot revoke
refresh tokens.
"""

from datetime import datetime
from datetime import timezone

from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import String

from app.db.database import Base


class RefreshToken(Base):

    __tablename__ = "refresh_tokens"

    # Primary Key
    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    # Owner
    user_id = Column(
        Integer,
        nullable=False,
        index=True
    )

    # Refresh JWT
    token = Column(
        String(512),
        nullable=False,
        unique=True,
        index=True
    )

    # Logout -> True
    is_revoked = Column(
        Boolean,
        default=False,
        nullable=False
    )

    # Created Time
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(
            timezone.utc
        )
    )

    # Expiry Time
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False
    )


#main
from fastapi import FastAPI

from app.db.database import (
    Base,
    engine
)

# Import Models
from app.models.refresh_token import RefreshToken

from app.routes.auth_routes import router as auth_router
from app.routes.user_routes import router as user_router
from app.routes.admin_routes import router as admin_router

# Create tables
Base.metadata.create_all(
    bind=engine
)

app = FastAPI()

app.include_router(auth_router)
app.include_router(user_router)
app.include_router(admin_router)


@app.get("/")
def root():

    return {
        "message": "Platform Service is running"
    }

authserv
from datetime import timedelta

from app.db.database import SessionLocal
from app.models.refresh_token import RefreshToken

from app.core.config import REFRESH_TOKEN_EXPIRE_DAYS

#above loginuser
def save_refresh_token(
    user_id: int,
    token: str
):
    """
    Stores refresh token in database.

    Called immediately after
    successful login.
    """

    db = SessionLocal()

    try:

        refresh = RefreshToken(

            user_id=user_id,

            token=token,

            expires_at=datetime.now(
                timezone.utc
            ) + timedelta(
                days=REFRESH_TOKEN_EXPIRE_DAYS
            )

        )

        db.add(refresh)

        db.commit()

    finally:

        db.close()
    #afyer these refresh_token = create_refresh_token(
    {
        "sub": user["email"],
        "user_id": user["user_id"]
    }
)
add it save_refresh_token(
    user["user_id"],
    refresh_token
)
uthservumice def get_valid_refresh_token(
    token: str
):
    """
    Returns refresh token only if

    1. Exists
    2. Not revoked
    """

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
            return None

        if refresh.is_revoked:
            return None

        return refresh

    finally:

        db.close()

    @router.post(
    "/refresh",
    response_model=AccessTokenResponse
)
def refresh_token(
    body: RefreshRequest
):

    refresh = get_valid_refresh_token(
        body.refresh_token
    )

    if refresh is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token revoked or invalid"
        )

    try:

        payload = decode_token(
            body.refresh_token
        )

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

    user = users.get(
        payload.get("sub")
    )

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
class LogoutRequest(BaseModel):
    refresh_token: str
    Add this function below get_valid_refresh_toke
    ).

def revoke_refresh_token(
    token: str
):
    """
    Marks a refresh token as revoked.

    Revoked tokens can no longer
    be used to generate new
    access tokens.
    """

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
