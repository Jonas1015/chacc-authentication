from typing import Union

from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    passwordConfirm: str
    first_name: str | None = None
    last_name: str | None = None


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str
    access_token_expires_at: str | None = None
    access_token_expiry: int | None = None
    refresh_token_expiry: int | None = None


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class RevokeRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    uuid: str
    username: str
    first_name: Union[str, None] = None
    middle_name: Union[str, None] = None
    last_name: Union[str, None] = None
    email: str
    is_active: bool
