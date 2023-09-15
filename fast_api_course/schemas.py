from pydantic import BaseModel


class ToDo(BaseModel):
    title: str
    description: str
    completed: bool = False

    class Config:
        from_attributes = True

