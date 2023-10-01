from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, FLOAT, Numeric
from sqlalchemy.orm import relationship
from database import Base


class ToDo(Base):

    __tablename__ = 'ToDo'

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String, index=True)
    completed = Column(Boolean)


class Product(Base):

    __tablename__ = "Product"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    price = Column(Numeric, index=True)
    count = Column(Integer, default=0, index=True)
    description = Column(String, index=True)
    