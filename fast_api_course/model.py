import re
import bcrypt
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, FLOAT, Numeric, CheckConstraint
from sqlalchemy.orm import relationship, validates
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


class User(Base):

    __tablename__ = 'User'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    age = Column(Integer, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    password = Column(String, nullable=False, index=True)
    telephone_number = Column(String, unique=True)

    @validates('email')
    def validate_email(self, key, email):
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError("Invalid email address")
        return email

    @validates('password')
    def validate_password(self, key, password):
        if 8 <= len(password) <= 16:
            salt = bcrypt.gensalt()  # Generate a salt (this is random)
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed_password
        raise ValueError("Invalid password")

    @validates('telephone_number')
    def validate_tel_number(self, key, number):
        print(len(number))
        print(number[0])
        print(number[1:])
        print(number[1:].isdigit())
        if len(number) == 13 and number[0] == '+' and number[1:].isdigit():
            return number
        raise ValueError("Invalid telephone number")

    __table_args__ = (
        CheckConstraint('age >= 0', name="Check positive integer for age"),
    )
