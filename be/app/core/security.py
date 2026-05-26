from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.schemas.auth import TokenData, UserOut

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def authenticate_user(username: str, password: str, db: Session) -> UserOut | None:
    from app.db.models.user import User

    user = (
        db.query(User)
        .filter(User.username == username, User.is_active.is_(True))
        .first()
    )
    if not user or not verify_password(password, user.hashed_password):
        return None
    return UserOut(username=user.username, roles=user.roles)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.jwt_secret, algorithm="HS256")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> UserOut:
    if not settings.auth_enabled:
        return UserOut(username="local", roles=["admin"])

    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        username: str | None = payload.get("sub")
        roles: list[str] = payload.get("roles", [])
        if not username:
            raise credentials_exc
        token_data = TokenData(username=username, roles=roles)
    except JWTError as exc:
        raise credentials_exc from exc

    from app.db.models.user import User

    user = (
        db.query(User)
        .filter(User.username == token_data.username, User.is_active.is_(True))
        .first()
    )
    if not user:
        raise credentials_exc

    return UserOut(username=user.username, roles=user.roles)


def require_roles(allowed_roles: list[str]):
    def _require(user: UserOut = Depends(get_current_user)) -> UserOut:
        if not any(r in user.roles for r in allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return _require
