from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext
from typing import Optional
from datetime import datetime, timedelta
import json

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

user_db = {
    "asdf" : {
        "username": "asdf",
        "full_name": "ASDF",
        "hashed_password": "$2b$12$EEcTaLvmkd86YT/hbkaXf.r9Wd5vsgI7E8H3emOiPoWw/J5DwA992",
        "disabled": False
    },

    "admin" : {
        "username": "admin",
        "full_name": "Jeffrey Bezos",
        "hashed_password": "$2b$12$xzLsXOPRkLXtpAcfQaPHdOyf1sIX4AV29anwXvjsLAbqDBdue3Hau",
        "disabled": False
    }

}

with open("db.json", "r") as read_file:
    data = json.load(read_file)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()
menu = data["menu"]



class Item(BaseModel):
    id: int
    nama: str

class User(BaseModel):
    username: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

### AUTH ###

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires:
        expire = datetime.utcnow() + expires
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(user_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

### CRUD ###

@app.get("/")
async def root():
    return {"Home":"Home Page"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(user_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data = {"sub": user.username}, expires = access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model = User)
async def read_users_me(current_user : User = Depends(get_current_active_user)):
    return current_user

@app.get("/menu")
async def read_menu(current_user : User = Depends(get_current_active_user)):
    return menu

@app.post("/add-menu")
async def add_menu(name: str, current_user : User = Depends(get_current_active_user)):
    id = 1
    if (len(menu) > 0):
        id = menu[len(menu)-1]['id']+1
    new_item = {'id':id, 'name':name}
    menu.append(dict(new_item))
    read_file.close()
    with open("db.json", "w") as write_file:
        json.dump(data, write_file, indent=4)
    write_file.close()
    return new_item

@app.get("/get-menu/{id}")
async def get_menu(id: int, current_user : User = Depends(get_current_active_user)):
    for menu_item in menu:
        if menu_item['id'] == id:
            return menu_item
    raise HTTPException(
        status_code=404, detail=f'Item not found'
    )

@app.put("/update-menu/{id}")
async def update_menu(id: int, name: str, current_user : User = Depends(get_current_active_user)):
    for menu_item in menu:
        if menu_item['id'] == id:
            menu_item['name'] = name
            read_file.close()
            with open("db.json", "w") as write_file:
                json.dump(data, write_file, indent=4)
            write_file.close()
            return {"message": "Item Updated Successfully"}
    raise HTTPException(
        status_code=404, detail=f'Item not found'
    )

@app.delete("/del-menu/{id}")
async def delete_menu(id: int, current_user : User = Depends(get_current_active_user)):
    for menu_item in menu:
        if menu_item['id'] == id:
            menu.remove(menu_item)
            read_file.close()
            with open("db.json", "w") as write_file:
                json.dump(data, write_file, indent=4)
            write_file.close()
            return {"message": "Item Deleted Successfully"}
    raise HTTPException(
        status_code=404, detail=f'Item not found'
    )

