from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    roles: list[str]


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenData(BaseModel):
    username: str | None = None
    roles: list[str] = []


class UserOut(BaseModel):
    username: str
    roles: list[str]
