from datetime import timedelta, timezone, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.security import (
    authenticate_user,
    blocklist_token,
    create_token_pair,
    get_current_user,
    oauth2_scheme,
)
from app.db.session import get_db
from app.schemas.auth import RefreshRequest, Token, UserOut

router = APIRouter()


@router.post("/token", response_model=Token)
@limiter.limit("10/minute")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> Token:
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        try:
            from app.core.metrics import AUTH_FAILURES_TOTAL
            AUTH_FAILURES_TOTAL.labels(reason="bad_credentials").inc()
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access, refresh = create_token_pair(
        data={"sub": user.username, "roles": user.roles}
    )
    return Token(access_token=access, refresh_token=refresh, roles=user.roles)


@router.post("/refresh", response_model=Token)
@limiter.limit("10/minute")
def refresh_token(request: Request, body: RefreshRequest, db: Session = Depends(get_db)) -> Token:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(body.refresh_token, settings.jwt_secret, algorithms=["HS256"])
    except JWTError:
        raise credentials_exc

    if payload.get("type") != "refresh":
        raise credentials_exc

    username: str | None = payload.get("sub")
    roles: list[str] = payload.get("roles", [])
    jti: str | None = payload.get("jti")

    if not username or not jti:
        raise credentials_exc

    # Blocklist old refresh token
    exp = payload.get("exp", 0)
    remaining = max(0, int(exp - datetime.now(timezone.utc).timestamp()))
    blocklist_token(jti, remaining)

    # Verify user still active
    from app.db.models.user import User
    user = db.query(User).filter(User.username == username, User.is_active.is_(True)).first()
    if not user:
        raise credentials_exc

    access, new_refresh = create_token_pair(data={"sub": user.username, "roles": user.roles})
    return Token(access_token=access, refresh_token=new_refresh, roles=user.roles)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    token: str = Depends(oauth2_scheme),
) -> None:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        jti: str | None = payload.get("jti")
        exp = payload.get("exp", 0)
        if jti:
            remaining = max(0, int(exp - datetime.now(timezone.utc).timestamp()))
            blocklist_token(jti, remaining or 60)
    except JWTError:
        pass  # Already invalid — nothing to revoke


@router.get("/me", response_model=UserOut)
def me(current_user: UserOut = Depends(get_current_user)) -> UserOut:
    return current_user
