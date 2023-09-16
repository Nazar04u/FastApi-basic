from typing import Union, Optional
from pydantic import BaseModel, EmailStr, PositiveInt


class User(BaseModel):
    name: str
    email: EmailStr
    age: Optional[PositiveInt] = None,
    is_subscribed: Union[bool, None] = None


class Feedback(BaseModel):
    name: str
    message: str


class Product(BaseModel):
    product_id: int
    name: str
    category: str
    price: float


class FilterProduct(BaseModel):
    keyword: str
    category: Union[str, None] = None
    limit: Union[int, None] = 10


class LoginUser(BaseModel):
    username: str
    password: str

