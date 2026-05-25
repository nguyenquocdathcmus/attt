from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    roles: list[str]


class TokenData(BaseModel):
    username: str | None = None
    roles: list[str] = []


class UserOut(BaseModel):
    username: str
    roles: list[str]
