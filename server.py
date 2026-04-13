from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import certifi
from pathlib import Path
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import asyncio

# ================= CONFIG =================

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mongo_url = os.environ['MONGO_URL']
db_name = os.environ['DB_NAME']

is_atlas = 'mongodb+srv' in mongo_url or 'mongodb.net' in mongo_url

client = AsyncIOMotorClient(
    mongo_url,
    serverSelectionTimeoutMS=10000,
    tlsCAFile=certifi.where() if is_atlas else None
)

db = client[db_name]

# ================= JWT =================

JWT_SECRET = os.environ.get('JWT_SECRET', 'change-this')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_DAYS = 7

# ================= EMAIL =================

MAIL_HOST = os.environ.get('MAIL_HOST', 'smtp.gmail.com')
MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
MAIL_FROM = os.environ.get('MAIL_FROM_ADDRESS', MAIL_USERNAME)

# ================= APP =================

app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

# ================= HELPERS =================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_token(user_id: str):
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRATION_DAYS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> Optional[Dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        logger.warning("Token expirado")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Token invalido")
        return None

def generate_code():
    return str(secrets.randbelow(1000000)).zfill(6)

def validate_password(password: str):
    return {
        "is_valid": (
            len(password) >= 8 and
            any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password)
        )
    }

# ================= EMAIL =================

async def send_email(to_email: str, subject: str, body: str):

    if not MAIL_USERNAME or not MAIL_PASSWORD:
        raise Exception("Email no configurado")

    def send():
        try:
            msg = MIMEMultipart()
            msg["From"] = MAIL_FROM
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "html"))

            server = smtplib.SMTP(MAIL_HOST, MAIL_PORT, timeout=10)
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
            server.quit()

            return True

        except Exception as e:
            logger.error(f"SMTP error: {e}")
            return False

    loop = asyncio.get_event_loop()

    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, send),
            timeout=15
        )

        if not result:
            raise Exception("Error enviando correo")

        return True

    except asyncio.TimeoutError:
        raise Exception("Timeout enviando correo")

# ================= MODELS =================

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    password_confirmation: str

class Login(BaseModel):
    email: EmailStr
    password: str

# ================= AUTH =================

@api_router.post("/register")
async def register(data: UserCreate):

    if data.password != data.password_confirmation:
        raise HTTPException(400, "Las contrasenas no coinciden")

    if not validate_password(data.password)["is_valid"]:
        raise HTTPException(400, "Contrasena debil")

    exists = await db.users.find_one({"email": data.email})
    if exists:
        raise HTTPException(400, "Correo ya registrado")

    user_id = str(uuid.uuid4())
    code = generate_code()

    await db.users.insert_one({
        "id": user_id,
        "email": data.email,
        "name": data.name,
        "password": hash_password(data.password),
        "verified": False
    })

    await db.codes.update_one(
        {"email": data.email},
        {"$set": {
            "code": hash_password(code),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10)
        }},
        upsert=True
    )

    await send_email(
        data.email,
        "Codigo de verificacion",
        f"<h1>{code}</h1>"
    )

    return {"msg": "Usuario creado"}

# ================= LOGIN =================

@api_router.post("/login")
async def login(data: Login):

    user = await db.users.find_one({"email": data.email})

    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(401, "Credenciales incorrectas")

    token = create_token(user["id"])

    return {"token": token}

# ================= USER =================

async def get_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(401, "No autenticado")

    payload = decode_token(creds.credentials)
    if not payload:
        raise HTTPException(401, "Token invalido")

    user = await db.users.find_one({"id": payload["user_id"]})

    if not user:
        raise HTTPException(404, "Usuario no encontrado")

    return user

@api_router.get("/me")
async def me(user=Depends(get_user)):
    return {"user": user["email"]}

# ================= APP =================

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"msg": "API funcionando"}

@app.on_event("startup")
async def startup():
    await client.admin.command("ping")
    logger.info("Mongo conectado")

@app.on_event("shutdown")
async def shutdown():
    client.close()
