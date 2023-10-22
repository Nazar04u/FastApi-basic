from fastapi.testclient import TestClient

print(__name__)
from main import app

client = TestClient(app)


def test_register_user():
    user_data = {
        'username': "Negan16",
        'age': 44,
        'email': "negan16@gmail.com",
        "password": "negan123",
        'phone': '+380991123416'}
    response = client.post('/register_user', json=user_data)
    assert response.status_code == 200
    assert response.json() == {
        'username': "Negan16",
        'age': 44,
        'email': "negan16@gmail.com",
        "password": "negan123",
        'phone': '+380991123416'}


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
    response = client.post('/login_user/?username=Negan5&password=negan123')
    assert response.status_code == 200
    assert response.json() == {
        "username": "Negan5",
        "age": 44,
        "email": "negan5@gmail.com",
        "password": "($2b$12$bHmw7r/hQtlbCxkT2UW97O5Xu6Vo8r1oXZij6w3F74Mu49UlS2BMe,$2b$12$bHmw7r/hQtlbCxkT2UW97O)",
        "phone": "Unknown"
    }


def test_get_user():
    response = client.get('/find_user/26')
    assert response.status_code == 200
    assert response.json() == {
        "username": "Negan5",
        "age": 44,
        "email": "negan5@gmail.com",
        "password": "($2b$12$bHmw7r/hQtlbCxkT2UW97O5Xu6Vo8r1oXZij6w3F74Mu49UlS2BMe,$2b$12$bHmw7r/hQtlbCxkT2UW97O)",
        "telephone_number": "+380991134445",
        'id': 26
    }


def test_delete_ToDo():
    response = client.delete('/delete_ToDo/2')
    assert response.status_code == 200
    assert response.json() == {"message": "Task was deleted."}