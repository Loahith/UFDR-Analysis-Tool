import os
import secrets
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson import ObjectId
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL")
client = MongoClient(MONGO_URL)
db = client["ufdr_db"]
users_collection = db["users"]
history_collection = db["history"]
sessions_collection = db["sessions"]

MAX_HISTORY_PER_USER = 50
SESSION_LIFETIME_HOURS = 24

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

def save_history_entry(username, entry):
    """Insert one analysis entry for this user, then prune older entries
    beyond MAX_HISTORY_PER_USER so the collection doesn't grow forever."""
    doc = dict(entry)
    doc["username"] = username
    history_collection.insert_one(doc)

    count = history_collection.count_documents({"username": username})
    if count > MAX_HISTORY_PER_USER:
        overflow = count - MAX_HISTORY_PER_USER
        old_docs = history_collection.find(
            {"username": username}
        ).sort("_id", 1).limit(overflow)
        old_ids = [d["_id"] for d in old_docs]
        if old_ids:
            history_collection.delete_many({"_id": {"$in": old_ids}})

def load_history_entries(username, limit=MAX_HISTORY_PER_USER):
    """Newest first, scoped to this user only."""
    docs = history_collection.find({"username": username}).sort("_id", -1).limit(limit)
    result = []
    for d in docs:
        d["id"] = str(d["_id"])
        del d["_id"]
        result.append(d)
    return result

def delete_history_entry(username, entry_id):
    """Delete one entry, but only if it belongs to this user."""
    try:
        oid = ObjectId(entry_id)
    except Exception:
        return False
    res = history_collection.delete_one({"_id": oid, "username": username})
    return res.deleted_count > 0

def create_session(username):
    """Called on successful login. Returns an opaque token to set as a cookie.
    The server â€” not the browser â€” is now the source of truth for identity."""
    token = secrets.token_urlsafe(32)
    sessions_collection.insert_one({
        "token": token,
        "username": username,
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(hours=SESSION_LIFETIME_HOURS),
    })
    return token

def get_username_from_session(token):
    """Returns the username for a valid, unexpired session token, else None."""
    if not token:
        return None
    session = sessions_collection.find_one({"token": token})
    if not session:
        return None
    if session["expires_at"] < datetime.utcnow():
        sessions_collection.delete_one({"_id": session["_id"]})
        return None
    return session["username"]

def delete_session(token):
    if token:
        sessions_collection.delete_one({"token": token})
