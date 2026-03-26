import os, logging
import datetime, random, string
import jwt
from dotenv import load_dotenv
load_dotenv()

from typing import Optional, Dict
from fastapi import Request, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext

logger = logging.getLogger("asdip.auth")
security = HTTPBearer()

# Configurations (Should be in .env)
SECRET_KEY = os.environ.get("ASDIP_SECRET_KEY", "super-secret-key-ASDIP-v5")
if not SECRET_KEY or "super-secret" in SECRET_KEY:
    raise RuntimeError("ASDIP_SECRET_KEY must be set securely in environment")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthManager:
    """
    Handles authentication, JWT generation, and verification.
    """
    @staticmethod
    def get_password_hash(password: str) -> str:
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
        to_encode = data.copy()
        # Multi-tenancy: default to 'common' if not provided
        if "tenant_id" not in to_encode:
            to_encode["tenant_id"] = "default"
        if "role" not in to_encode:
            to_encode["role"] = "user"

        if expires_delta:
            expire = datetime.datetime.utcnow() + expires_delta
        else:
            expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {e}")
            return None

    @staticmethod
    def generate_otp() -> str:
        return ''.join(random.choices(string.digits, k=6))

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    """Dependency to check for valid JWT."""
    token = credentials.credentials
    payload = AuthManager.verify_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload

def check_role(required_role: str):
    """Dependency for RBAC."""
    def role_checker(user: dict = Depends(get_current_user)):
        if user.get("role") != required_role and user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return role_checker

# Simple mock user database
ADMIN_USER = os.environ.get("ASDIP_ADMIN_USER", "admin")
_raw_hash = os.environ.get("ASDIP_ADMIN_PASS_HASH", "")
ADMIN_PASS_HASH = _raw_hash.strip().strip("'").strip('"') if _raw_hash else None

def authenticate_admin(username: str, password: str) -> Optional[dict]:
    if ADMIN_PASS_HASH and username == ADMIN_USER and AuthManager.verify_password(password, ADMIN_PASS_HASH):
        return {"sub": username, "role": "admin", "tenant_id": "system"}
    return None

async def authenticate_user(username: str, password: str) -> Optional[dict]:
    from core.db import db
    # Check admin first
    admin = authenticate_admin(username, password)
    if admin: return admin
    
    user = await db.get_user_by_username(username)
    if user and AuthManager.verify_password(password, user["password"]):
        return {"sub": username, "email": user["email"], "role": user.get("role", "user"), "tenant_id": user.get("tenant_id", "default")}
    return None
