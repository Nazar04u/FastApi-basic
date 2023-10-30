import unittest

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from main import app, get_db
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker
from model import User, Product, ToDo
from config import DB_PORT_TEST, DB_HOST_TEST, DB_PASS_TEST, DB_USER_TEST, DB_NAME_TEST

SQLALCHEMY_DATABASE_URL = f"postgresql://{DB_USER_TEST}:{DB_PASS_TEST}@{DB_HOST_TEST}:{DB_PORT_TEST}/{DB_NAME_TEST}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
Base.metadata.create_all(bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


def test_delete_user():
    response = client.delete(f'/delete_user/15')
    assert response.status_code == 200
    assert response.json() == {"message": "User is deleted"}


def test_register_user():
    user_data = {
        'username': "Negan1",
        'age': 44,
        'email': "negan1@gmail.com",
        "password": "negan123",
        'phone': '+380991123411'}
    response = client.post('/register_user', json=user_data)
    assert response.status_code == 200
    assert response.json() == {
        'username': "Negan1",
        'age': 44,
        'email': "negan1@gmail.com",
        "password": "negan123",
        'phone': '+380991123411'}


def test_calculate_sum():
    response = client.get("/sum/?a=5&b=10")
    assert response.status_code == 200
    assert response.json() == {"result": 15}

    response = client.get("/sum/?a=-8&b=-3")
    assert response.status_code == 200
    assert response.json() == {"result": -11}

    # Test case 3: ноль и положительное число
    response = client.get("/sum/?a=0&b=7")
    assert response.status_code == 200
    assert response.json() == {"result": 7}


def test_login_user():
    response = client.post('/login_user/?username=Negan&password=negan123')
    assert response.status_code == 200
    assert response.json() == {
        "username": "Negan",
        "age": 44,
        "email": "negan@gmail.com",
        "password": "($2b$12$H4WgaNwpQeem12L96ne9F.YR92UjJxUn0hrf/l.JZ6nEPm9tcLcVS,$2b$12$H4WgaNwpQeem12L96ne9F.)",
        "phone": "Unknown"
    }


def test_get_user():
    response = client.get('/find_user/12')
    assert response.status_code == 200
    assert response.json() == {
        "username": "Negan",
        "age": 44,
        "email": "negan@gmail.com",
        "password": "($2b$12$H4WgaNwpQeem12L96ne9F.YR92UjJxUn0hrf/l.JZ6nEPm9tcLcVS,$2b$12$H4WgaNwpQeem12L96ne9F.)",
        "telephone_number": "+380991123421",
        'id': 12
    }


# Test mocking
class TestExternal_API(unittest.TestCase):
    @patch('main.get_data_from_api')
    @patch('main.process_data')
    def test_external_api(self, mock_process_data, mock_fetch_data):
        mock_response = {'data': 'I am the best!', 'fact': 'I am the best'}
        mock_fetch_data.return_value = mock_response

        mock_processed_data = {'data': 'I am the best'}
        mock_process_data.return_value = mock_processed_data

        response = client.get('/Fetch_data_from_API')

        mock_fetch_data.assert_called_once()
        mock_process_data.assert_called_once_with(mock_response)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), mock_processed_data)
