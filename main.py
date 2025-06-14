from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import jwt
import datetime
import time
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64
from dotenv import load_dotenv
import os
from api.authmodels import LoginRequest, TokenResponse

app = FastAPI()
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable not set")

des_key = os.getenv("DES_KEY", "").encode()
raw_3des_key = os.getenv("DES3_KEY", "").encode()
aes_key = os.getenv("AES_KEY", "").encode()

if not des_key or not raw_3des_key or not aes_key:
    raise RuntimeError("DES/3DES/AES key environment variables not properly set.")

des3_key = DES3.adjust_key_parity(raw_3des_key)



def encrypt_des(data, key):
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data.encode(), DES.block_size))
    return base64.b64encode(iv + ct).decode()


def encrypt_3des(data, key):
    iv = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data.encode(), DES3.block_size))
    return base64.b64encode(iv + ct).decode()


def encrypt_aes(data, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(iv + ct).decode()


def create_token(username, des, des3, aes, exp_time):
    payload = {
        'user': username,
        'des': des,
        '3des': des3,
        'aes': aes,
        'exp': exp_time
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


@app.post("/login", response_model=TokenResponse)
def login(request: LoginRequest):
    if not request.username or not request.password:
        raise HTTPException(status_code=400, detail="Username and password required")

    
    
    start_des = time.perf_counter()
    encrypted_des = encrypt_des(request.password, des_key)
    end_des = time.perf_counter()

    
    start_3des = time.perf_counter()
    encrypted_3des = encrypt_3des(request.password, des3_key)
    end_3des = time.perf_counter()

    
    start_aes = time.perf_counter()
    encrypted_aes = encrypt_aes(request.password, aes_key)
    end_aes = time.perf_counter()

    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)

    token = create_token(
        request.username,
        encrypted_des,
        encrypted_3des,
        encrypted_aes,
        exp_time=expiration_time
    )

    return {
        "token": token,
        "encrypted_passwords": {
            "DES": encrypted_des,
            "3DES": encrypted_3des,
            "AES": encrypted_aes
        },
        "encryption_times_seconds": {
            "DES": f"{end_des - start_des:.8f}",
            "3DES": f"{end_3des - start_3des:.8f}",
            "AES": f"{end_aes - start_aes:.8f}"
        },
        "token_expiration_utc": expiration_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }


@app.get("/protected")
def protected(token: str = Header(..., alias="x-access-token")):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = payload.get("user")
    return {"message": f"Hello {user}, you accessed a protected route!"}
