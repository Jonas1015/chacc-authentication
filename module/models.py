from chacc_api import ChaCCBaseModel, register_model
from sqlalchemy import Column, String, Boolean
from pydantic import BaseModel


@register_model
class User(ChaCCBaseModel):
    __tablename__ = "users"
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    role = Column(String, default="user", nullable=False)  # e.g., user, admin


# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    role: str