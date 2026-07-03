import os
from pymongo import MongoClient
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL")
client = MongoClient(MONGO_URL)
db = client["ufdr_db"]
users_collection = db["users"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_user(username, email, password):
    if users_collection.find_one({"username": username}):
        return False, "Username already exists"
    if users_collection.find_one({"email": email}):
        return False, "Email already exists"
    users_collection.insert_one({
        "username": username,
        "email": email,
        "hashed_password": pwd_context.hash(password)
    })
    return True, "User created"

def verify_user(username, password):
    user = users_collection.find_one({"username": username})
    if not user:
        return False
    return pwd_context.verify(password, user["hashed_password"])