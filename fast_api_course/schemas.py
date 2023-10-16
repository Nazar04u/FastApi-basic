from typing import Optional

from fastapi_localization import TranslatableStringField
from pydantic import BaseModel, conint, constr, EmailStr


class ToDo(BaseModel):
    title: str
    description: str
    completed: bool = False

    class Config:
        from_attributes = True


class Product(BaseModel):
    title: str
    price: int | float
    count: int = 0
    description: str

    class Config:
        from_attributes = True


class ErrorResponse(BaseModel):
    status: int
    message: str
    error_code: int


class User(BaseModel):
    username: str
    age: conint(gt=18)
    email: EmailStr
    password: str
    phone: Optional[str] = 'Unknown'

    class Config:
        from_attributes = True


class LanguageTranslatableSchema(BaseModel):
    code: str
    title: TranslatableStringField

    class Config:
        arbitrary_types_allowed = True

