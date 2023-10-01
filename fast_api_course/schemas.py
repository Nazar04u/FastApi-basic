from pydantic import BaseModel


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