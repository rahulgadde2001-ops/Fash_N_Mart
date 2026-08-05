authserv
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from app.schemas.user import Role
from app.core.security import hash_password, verify_password

from app.core.security import (
    create_access_token,
    create_refresh_token
)  
from app.database import SessionLocal
from app.models.refresh_token import RefreshToken
from app.models.failed_login import FailedLoginAttempt

login_attempts = {}

MAX_ATTEMPTS = 5
WINDOW = timedelta(minutes=15)

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


users = {
    "ceo@company.com": {
        "user_id": 1,
        "email": "ceo@company.com",
        "password": hash_password("ceo@company12"),
        "full_name": "Company CEO",
        "role": Role.ceo,
        "is_active": True,
    },
    "warehousemanager@company.com": {
        "user_id": 2,
        "email": "warehousemanager@company.com",
        "password": hash_password("warehouse@123"),
        "full_name": "Warehouse Manager",
        "role": Role.warehouse_manager,
        "is_active": True,
    },
    "vpoperations@company.com":{
                "user_id": 3,
                "email": "vpoperations@company.com",
                "password": hash_password("vpoperations@12"),
                "full_name": "vp_operations Manager",
                "role": Role.vp_operations,
                "is_active": True,
    },
    "procurementmanager@company.com":{
                "user_id":4,
                "email":"procurementmanager@company.com",
                "password":hash_password("procurement@123"),
                "full_name":"procurement_manager",
                "role":Role.procurement_manager,
                "is_active":True,

    },
     "logisticsmanager@company.com":{
                    "user_id":5,
                    "email":"logisticsmanager@company.com",
                    "password":hash_password("logistics123"),
                    "full_name":"logistics_manager",
                    "role":Role.logistics_manager,
                    "is_active":True,
     },
    "compliance@company.com":{
                    "user_id":6,
                    "email":"compliance@company.com",
                    "password":hash_password("compliance@12"),
                    "full_name":"compliance_officer",
                    "role":Role.compliance_officer,
                    "is_active":True,
    },
    "analyst@company.com":{
                            "user_id":7,
                            "email":"analyst@company.com",
                            "password":hash_password("analyst@1234"),
                            "full_name":"analyst",
                            "role":Role.analyst,
                            "is_active":True,
    },
    "supplier@company.com":{
                            "user_id":8,
                            "email":"supplier@company.com",
                            "password":hash_password("supplier@123"),
                            "full_name":"supplier",
                            "role":Role.supplier,
                            "is_active":True,
    }
        
}


def login(username: str, password: str):

    user = users.get(username)

    if user is None:
        return None

    if not verify_password(password, user["password"]):
        return None

    return user


authroute 
from fastapi import APIRouter , HTTPException,Depends, Request,status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError

from app.core.config import TRUST_PROXY
from app.services.auth_service import (
    login_user,
    users,
    get_refresh_token,
    revoke_refresh_token 
)
from app.schemas.auth import (
    TokenResponse,
    RefreshRequest,
    AccessTokenResponse,
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

@router.post(
"/login",
response_model=TokenResponse
)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    return login_user(
        username=form_data.username,
        password=form_data.password,
        client_ip=get_client_ip(request)
    )


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

test 
def test_logout_revokes_refresh_token():
    clear_attempts()

    login = login_as_ceo()
    refresh = login.json()["refresh_token"]

    logout = client.post(
        "/api/v1/auth/logout",
        json={
            "refresh_token": refresh
        }
    )

    assert logout.status_code == 200

    response = client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": refresh
        }
    )

    assert response.status_code == 401


def test_ceo_has_vp_permissions():
    clear_attempts()

    login = login_as_ceo()

    token = login.json()["access_token"]

    response = client.get(
        "/api/v1/auth/me/permissions",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200

    permissions = response.json()["permissions"]

    assert "vp_operations" in permissions


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


ROLE_HIERARCHY = {
    "ceo": {
        "ceo",
        "vp_operations",
        "procurement_manager",
        "logistics_manager",
        "compliance_officer",
        "warehouse_manager",
        "analyst",
        "supplier",
    },
    "vp_operations": {
        "vp_operations",
        "procurement_manager",
        "logistics_manager",
        "compliance_officer",
        "warehouse_manager",
        "analyst",
        "supplier",
    },
    "procurement_manager": {
        "procurement_manager"
    },
    "logistics_manager": {
        "logistics_manager"
    },
    "compliance_officer": {
        "compliance_officer"
    },
    "warehouse_manager": {
        "warehouse_manager"
    },
    "analyst": {
        "analyst"
    },
    "supplier": {
        "supplier"
    },
}

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

db from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.config import DATABASE_URL

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
DATABASE_URL=sqlite:///./platform.db
