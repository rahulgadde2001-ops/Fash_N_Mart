def save_refresh_token(user_id: int, token: str, expires_at):

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
            .filter(RefreshToken.token == token)
            .first()
        )

        if refresh is None:
            return False

        refresh.is_revoked = True

        db.commit()

        return True

    finally:
        db.close()

def log_failed_login(email: str, ip_address: str):

    db = SessionLocal()

    try:
        db.add(
            FailedLoginAttempt(
                email=email,
                ip_address=ip_address
            )
        )

        db.commit()

    finally:
        db.close()

def login_user(
    username: str,
    password: str,
    client_ip: str
):

    now = datetime.now(timezone.utc)
    # Key on (email, ip) so a few bad attempts for one account cannot lock out
    # every other user sharing that IP (NAT / office network / load balancer).
    key = (username.lower(),client_ip)

    attempts = [
        t for t in login_attempts.get(key,[])
        if now - t < WINDOW
    ]

    if len(attempts) >= MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again after 15 minutes."
        )

    user = login(username, password)

    if not user:

        attempts.append(now)

        login_attempts[key] = attempts

        log_failed_login(
            email=username,
            ip_address=client_ip
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    if not user["is_active"]:
        log_failed_login(
            email=username,
            ip_address=client_ip
        )
        
        raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User account is inactive"
                )

    login_attempts.pop(key, None)

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
    expires_at=datetime.now(timezone.utc) + timedelta(days=7)
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

def login(username: str, password: str):

    user = users.get(username)

    if user is None:
        return None

    if not verify_password(password, user["password"]):
        return None

    return user

@router.post(
"/refresh",
response_model=AccessTokenResponse
)

def refresh_token(body: RefreshRequest):
    refresh = get_refresh_token(body.refresh_token)

    if refresh is None:
        raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or revoked refresh token"
    )

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
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Integer, String 
from app.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    token = Column(String(512), unique=True, nullable=False, index=True)
    is_revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=False)
