import requests, jwt
from fastapi import FastAPI, Cookie, Response, Header, Request, Depends, HTTPException
from datetime import datetime
import random, string
import model
import schemas
from starlette import status
from sqlalchemy.orm import Session
from models.models import Feedback, User, Product, FilterProduct, LoginUser
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
from datetime import datetime
from database import SessionLocal, engine
print(4)


app = FastAPI()
print(0)
model.Base.metadata.create_all(bind=engine)
print(5)
security = HTTPBasic()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
SECRET_KEY = 'The_Walking_Dead'
ALGORITHM = 'HS256'

# Пример пользовательских данных (для демонстрационный целей)
fake_users = {
    1: {"username": "john_doe", "email": "john@example.com"},
    2: {"username": "jane_smith", "email": "jane@example.com"},
}

sample_product_1 = {
    "product_id": 123,
    "name": "Smartphone",
    "category": "Electronics",
    "price": 599.99
}

sample_product_2 = {
    "product_id": 456,
    "name": "Phone Case",
    "category": "Accessories",
    "price": 19.99
}

sample_product_3 = {
    "product_id": 789,
    "name": "Iphone",
    "category": "Electronics",
    "price": 1299.99
}

sample_product_4 = {
    "product_id": 101,
    "name": "Headphones",
    "category": "Accessories",
    "price": 99.99
}

sample_product_5 = {
    "product_id": 202,
    "name": "Smartwatch",
    "category": "Electronics",
    "price": 299.99
}

sample_products = [sample_product_1, sample_product_2, sample_product_3, sample_product_4, sample_product_5]
users = {}
USER_DATA = {'admin': {'username': 'admin', 'password': 'admin', 'role': 'admin', 'access': ['create', 'read', 'update',
                                                                                             'delete']},
             'user': {'username': 'user', 'password': 'user', 'role': "user", 'access': ['read', 'update']},
             'quest': {'username': 'quest', 'password': 'quest', 'role': "quest", 'access': ['read', 'update']}}


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Конечная точка для получения информации о пользователе по ID
@app.get("/users/{user_id}")
def read_user(user_id: int):
    if user_id in fake_users:
        return fake_users[user_id]
    return {"error": "User not found"}


@app.get("/users/")
def read_users(limit: int = 2):
    return dict(list(fake_users.items())[:limit])


@app.post('/feedback')
async def send_feedback(feedback: Feedback):
    return {'message': f'Feedback received. Thank you, {feedback.name}!'}


@app.post('/create_user')
async def create_user(user: User) -> User:
    return user


@app.get('/product/{product_id}')
async def get_product(product_id: int):
    for sample in sample_products:
        if sample['product_id'] == product_id:
            return Product(**sample)
    return {'message': "Product not found"}


@app.get('/products/search')
async def get_filtered_products(filtered_products: FilterProduct):
    keyword = filtered_products.keyword
    category = filtered_products.category
    limit = filtered_products.limit
    list_filtered_products = []
    for sample in sample_products:
        if keyword.lower() in sample['name'].lower():
            if category is not None:
                if category == sample['category']:
                    list_filtered_products.append(sample)
            else:
                list_filtered_products.append(sample)
    if len(list_filtered_products) < limit:
        limit = len(list_filtered_products)
    return list_filtered_products[:limit]


@app.get('/products_2/search')
async def get_filtered_products(keyword: str, category: str = None, limit: int = None):
    list_filtered_products = []
    for sample in sample_products:
        if keyword.lower() in sample['name'].lower():
            if category is not None:
                if category == sample['category']:
                    list_filtered_products.append(sample)
            else:
                list_filtered_products.append(sample)
    if len(list_filtered_products) < limit:
        limit = len(list_filtered_products)
    return list_filtered_products[:limit]


@app.get("/")
def root(response: Response):
    now = datetime.now()
    response.set_cookie(key="last_visit", value=now)
    return {"message": "Cookies is installed"}


@app.post('/login')
async def login(login_user: LoginUser, response: Response):
    characters = string.ascii_letters + string.digits
    session_token = ''.join(random.choice(characters) for _ in range(12))
    print(session_token)
    response.set_cookie(key='session_token', value=session_token, secure=True)
    users[session_token] = login_user
    print(response)
    return {'message': 'You are successfully registered'}


@app.get('/user')
async def register(session_token: str | None):
    print(users.keys())
    for s_token in users.keys():
        if s_token == session_token:
            return users[session_token]
    return {"message": 'User is unauthorized'}


@app.get("/1")
def root(user_agent: str = Header()):
    return {"User-Agent": user_agent}


@app.get("/2")
def root():
    data = "Hello from here"
    response = Response(content=data, media_type="text/plain", headers={"Secret-Code": "123459"})
    print(response.headers)
    return response


@app.get("/headers")
async def get_headers(request: Request):
    return {"User-Agent": request.headers.get('user-agent'),
            "Accept_Language": request.headers.get('accept-language')}


def get_user(username: str):
    for user in USER_DATA:
        if username == user.username:
            return user
    return None


def authorization(credentials: HTTPBasicCredentials = Depends(security)):
    user = get_user(credentials.username)
    if user is None or user.password != credentials.password:
        return HTTPException(status_code=401, detail="Invalid data", headers={"WWW-Authenticate": "Basic"})
    else:
        return user


@app.get('/authorization')
async def get_protected_source(user: LoginUser = Depends(authorization)):
    return {"message": f"You successfully authorize!", "user_info": user}


@app.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}


def create_jwt_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


# Функция получения User'а по токену - это скорее всего была самая сложная часть в предыдущем задании
def get_user_from_token(token: str = Depends(oauth2_scheme)):
    try:
        print(token)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(payload)
        return payload.get("sub") # тут мы идем в полезную нагрузку JWT-токена и возвращаем утверждение о юзере (subject); обычно там еще можно взять "iss" - issuer/эмитент, или "exp" - expiration time - время 'сгорания' и другое, что мы сами туда кладем
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Функция для получения пользовательских данных на основе имени пользователя
def get_user(username: str):
    print(username)
    if username in USER_DATA:
        user_data = USER_DATA[username]
        return {"USER": LoginUser(username=user_data['username'], password=user_data['password']), 'user_data': user_data}
    return None


# Роут для получения JWT-токена (так работает логин)
@app.post("/token/")
def login(user_data: Annotated[OAuth2PasswordRequestForm, Depends()]): # тут логинимся через форму
    print(user_data.username)
    user_data_from_db = get_user(user_data.username)
    print(user_data_from_db)
    if user_data_from_db is None or user_data.password != user_data_from_db["USER"].password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_jwt_token({"sub": user_data.username})
    header = {
        "Authorization": access_token
    }
    print(access_token)
    response = Response()
    response.headers["Authorization"] = f"Bearer {access_token}"
    return {"access_token": access_token}, response  # тут мы добавляем полезную нагрузку в токен, и говорим, что "sub" содержит значение username


# Защищенный роут для админов, когда токен уже получен
@app.get("/admin/")
def get_admin_info(current_user: str = Depends(get_user_from_token)):
    print(current_user)
    user_data = get_user(current_user)
    print(user_data)
    if user_data["user_data"]['role'] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    return {"message": f"Welcome {current_user}!", 'access': user_data["user_data"]['access']}


# Защищенный роут для обычных пользователей, когда токен уже получен
@app.get("/user/")
def get_user_info(current_user: str = Depends(get_user_from_token)):
    user_data = get_user(current_user)
    if user_data["user_data"]['role'] != "user":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    return {"message": f"Hello {current_user}!", 'access': user_data["user_data"]['access']}


@app.get('/quest')
async def get_quest_info(current_user: str = Depends(get_user_from_token)):
    user_data = get_user(current_user)
    if user_data['user_data']['role'] != 'quest':
        raise HTTPException(status_code=403, detail="Not authorized")
    return {"message": f'Hello {current_user}', 'access': user_data['user_data']['access']}


@app.get('/protected_resource')
async def get_protected_information(current_user: str = Depends(get_user_from_token)):
    user_data = get_user(current_user)
    if user_data["user_data"]['role'] == "quest":
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"secret_information": "I do not know what to write"}


@app.get('/update')
async def check_read(current_user:str = Depends(get_user_from_token)):
    user_data = get_user(current_user)
    if user_data["user_data"]['role'] == "quest":
        raise HTTPException(status_code=403, detail="Forbidden")
    return {'message': "You have rights to update this"}


@app.post('/create_ToDo', response_model=schemas.ToDo)
async def create_ToDo(todo: schemas.ToDo, db: Session = Depends(get_db)):
    todo_item = schemas.ToDo(**todo.dict())
    for item in db.query(model.ToDo).all():
        if item.title == todo_item.title and todo_item.description == item.description:
            return item
    db_todo = model.ToDo(title=todo_item.title, description=todo.description, completed=todo_item.completed)
    db.add(db_todo)
    db.commit()
    db.refresh(db_todo)
    print(db.query(model.ToDo).all())
    return db_todo