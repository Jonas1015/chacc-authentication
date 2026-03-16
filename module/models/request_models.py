from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str
    expires_in: int | None = None
    expires_at: str | None = None
    access_token_expiry: int | None = None
    refresh_token_expiry: int | None = None


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class RevokeRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    role: str