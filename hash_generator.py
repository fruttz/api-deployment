from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    hashed_pwd = pwd_context.hash(password)
    return hashed_pwd

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

password = "asdf"
hashed_pwd = hash_password(password)
#print(hashed_pwd)
print(verify_password("secret", "$2b$12$EEcTaLvmkd86YT/hbkaXf.r9Wd5vsgI7E8H3emOiPoWw/J5DwA992"))

