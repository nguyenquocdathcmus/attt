from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings
from app.schemas.auth import TokenData, UserOut

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": get_password_hash("admin123"),
        "roles": ["admin"],
    },
    "analyst": {
        "username": "analyst",
        "hashed_password": get_password_hash("analyst123"),
        "roles": ["analyst"],
    },
    "viewer": {
        "username": "viewer",
        "hashed_password": get_password_hash("viewer123"),
        "roles": ["viewer"],
    },
}


def authenticate_user(username: str, password: str) -> UserOut | None:
    user = users_db.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return UserOut(username=user["username"], roles=user["roles"])


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta
        if expires_delta
        else timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm="HS256")


def get_current_user(token: str = Depends(oauth2_scheme)) -> UserOut:
    if not settings.auth_enabled:
        return UserOut(username="local", roles=["admin"])

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        username: str | None = payload.get("sub")
        roles = payload.get("roles", [])
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username, roles=roles)
    except JWTError as exc:
        raise credentials_exception from exc

    user = users_db.get(token_data.username or "")
    if not user:
        raise credentials_exception

    return UserOut(username=user["username"], roles=user["roles"])


def require_roles(allowed_roles: list[str]):
    def _require(user: UserOut = Depends(get_current_user)) -> UserOut:
        if not any(role in user.roles for role in allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return _require
