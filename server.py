from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import os
import logging
import certifi
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configure logging early
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
db_name = os.environ['DB_NAME']

# Use SSL/TLS only for Atlas connections (mongodb+srv or mongodb.net)
is_atlas = 'mongodb+srv' in mongo_url or 'mongodb.net' in mongo_url
if is_atlas:
    client = AsyncIOMotorClient(
        mongo_url,
        serverSelectionTimeoutMS=10000,
        tlsCAFile=certifi.where()
    )
    logger.info(f"MongoDB Atlas client configured - database: {db_name}")
else:
    client = AsyncIOMotorClient(
        mongo_url,
        serverSelectionTimeoutMS=10000
    )
    logger.info(f"MongoDB local client configured - database: {db_name}")

db = client[db_name]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'safewatch-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_DAYS = 7

# Email Configuration
MAIL_HOST = os.environ.get('MAIL_HOST', 'smtp.gmail.com')
MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
MAIL_FROM = os.environ.get('MAIL_FROM_ADDRESS', MAIL_USERNAME)

# Create the main app
app = FastAPI(title="SafeWatch API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============== MODELS ==============

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    password_confirmation: str
    phone: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    device_name: str = "web"

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    phone: Optional[str] = None
    role: str = "user"
    email_verified_at: Optional[str] = None

class TokenResponse(BaseModel):
    token: str
    user: UserResponse
    message: str

class EmailVerify(BaseModel):
    email: EmailStr
    code: str

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    email: EmailStr
    code: str
    password: str
    password_confirmation: str

class ChangePassword(BaseModel):
    current_password: str
    password: str
    password_confirmation: str

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None

class ContactCreate(BaseModel):
    name: str
    phone: str
    email: Optional[str] = None
    relationship: str
    is_primary: bool = False

class AlertCreate(BaseModel):
    type: str
    location: Dict[str, float]
    description: Optional[str] = None

class BackupCreate(BaseModel):
    name: str
    type: str

class AdminUserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone: Optional[str] = None
    role: str = "user"

class AdminUserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None

class MonitoringData(BaseModel):
    bpm: int
    spo2: int
    stress: int
    movement: float
    fall_detected: bool = False
    location: Optional[Dict[str, float]] = None

class EmergencyAlert(BaseModel):
    type: str  # 'fall', 'heart_attack', 'manual'
    location: Dict[str, float]
    monitoring_data: Optional[Dict] = None

# ============== HELPERS ==============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, device_name: str) -> str:
    payload = {
        'user_id': user_id,
        'device': device_name,
        'exp': datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRATION_DAYS),
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> Optional[Dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except:
        return None

def generate_code() -> str:
    return str(secrets.randbelow(1000000)).zfill(6)

def validate_password(password: str) -> Dict[str, Any]:
    """Validate password and return validation status for each requirement"""
    validations = {
        "min_length": len(password) >= 8,
        "has_uppercase": any(c.isupper() for c in password),
        "has_lowercase": any(c.islower() for c in password),
        "has_number": any(c.isdigit() for c in password),
        "has_special": any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password)
    }
    validations["is_valid"] = all([
        validations["min_length"],
        validations["has_uppercase"],
        validations["has_lowercase"],
        validations["has_number"]
    ])
    return validations

async def send_email(to_email: str, subject: str, body: str):
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        logger.warning(f"Email not configured. Would send to {to_email}: {subject}")
        return True
    
    import asyncio
    import concurrent.futures
    
    def _send_sync():
        try:
            msg = MIMEMultipart()
            msg['From'] = MAIL_FROM
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'html'))
            
            server = smtplib.SMTP(MAIL_HOST, MAIL_PORT, timeout=10)
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
            server.quit()
            return True
        except Exception as e:
            logger.error(f"Email error: {e}")
            return False
    
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _send_sync),
            timeout=15
        )
        return result
    except asyncio.TimeoutError:
        logger.error(f"Email timeout sending to {to_email}")
        return False
    except Exception as e:
        logger.error(f"Email error: {e}")
        return False

async def send_emergency_notification(user: Dict, emergency_type: str, location: Dict):
    """Send emergency notifications to all contacts"""
    contacts = await db.contacts.find({"user_id": user['id']}).to_list(100)
    
    type_names = {
        'fall': 'CAÍDA DETECTADA',
        'heart_attack': 'POSIBLE INFARTO',
        'manual': 'EMERGENCIA MANUAL'
    }
    
    subject = f"🚨 ALERTA DE EMERGENCIA - {type_names.get(emergency_type, 'EMERGENCIA')}"
    
    body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #dc2626; color: white; padding: 20px; text-align: center;">
            <h1>⚠️ ALERTA DE EMERGENCIA</h1>
        </div>
        <div style="padding: 20px; background: #f9fafb;">
            <h2 style="color: #dc2626;">{type_names.get(emergency_type, 'EMERGENCIA')}</h2>
            <p><strong>Usuario:</strong> {user['name']}</p>
            <p><strong>Tipo de emergencia:</strong> {type_names.get(emergency_type, emergency_type)}</p>
            <p><strong>Ubicación:</strong></p>
            <p>Latitud: {location.get('lat', 'N/A')}<br>Longitud: {location.get('lng', 'N/A')}</p>
            <p><a href="https://www.google.com/maps?q={location.get('lat', 0)},{location.get('lng', 0)}" 
                  style="background: #dc2626; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                Ver en Google Maps
            </a></p>
            <hr style="margin: 20px 0;">
            <p style="color: #666;">Este mensaje fue enviado automáticamente por SafeWatch.</p>
        </div>
    </div>
    """
    
    notified = []
    for contact in contacts:
        if contact.get('email'):
            await send_email(contact['email'], subject, body)
            notified.append(contact['name'])
    
    return notified

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="No autenticado")
    
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    
    user = await db.users.find_one({"id": payload['user_id']})
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    
    return user

async def require_admin(user = Depends(get_current_user)):
    if user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Acceso denegado")
    return user

def serialize_doc(doc):
    """Convert MongoDB document to JSON-serializable dict"""
    if doc is None:
        return None
    if isinstance(doc, list):
        return [serialize_doc(d) for d in doc]
    if isinstance(doc, dict):
        result = {}
        for key, value in doc.items():
            if key == '_id':
                continue  # Skip _id field
            elif isinstance(value, ObjectId):
                result[key] = str(value)
            elif isinstance(value, datetime):
                result[key] = value.isoformat()
            elif isinstance(value, dict):
                result[key] = serialize_doc(value)
            elif isinstance(value, list):
                result[key] = [serialize_doc(item) if isinstance(item, (dict, ObjectId)) else item for item in value]
            else:
                result[key] = value
        return result
    if isinstance(doc, ObjectId):
        return str(doc)
    if isinstance(doc, datetime):
        return doc.isoformat()
    return doc

# ============== PASSWORD VALIDATION ==============

@api_router.post("/auth/validate-password")
async def validate_password_endpoint(data: dict):
    """Validate password requirements in real-time"""
    password = data.get('password', '')
    return validate_password(password)

# ============== AUTH ROUTES ==============

@api_router.post("/auth/register")
async def register(data: UserCreate):
    # Validate password
    validation = validate_password(data.password)
    if not validation['is_valid']:
        raise HTTPException(status_code=400, detail="La contraseña no cumple los requisitos mínimos")
    
    if data.password != data.password_confirmation:
        raise HTTPException(status_code=400, detail="Las contraseñas no coinciden")
    
    existing = await db.users.find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="El correo ya está registrado")
    
    user_id = str(uuid.uuid4())
    code = generate_code()
    
    user = {
        "id": user_id,
        "name": data.name,
        "email": data.email,
        "password": hash_password(data.password),
        "phone": data.phone,
        "role": "user",
        "email_verified_at": None,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.users.insert_one(user)
    
    await db.email_verifications.update_one(
        {"email": data.email},
        {"$set": {
            "code": hash_password(code),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        }},
        upsert=True
    )
    
    email_body = f"""
    <h2>¡Bienvenido a SafeWatch!</h2>
    <p>Tu código de verificación es:</p>
    <h1 style="color: #10b981; font-size: 32px;">{code}</h1>
    <p>Este código expira en 30 minutos.</p>
    """
    await send_email(data.email, "Verifica tu correo - SafeWatch", email_body)
    
    return {
        "message": "Usuario registrado exitosamente. Por favor verifica tu correo electrónico.",
        "user": {"id": user_id, "name": data.name, "email": data.email}
    }

@api_router.post("/auth/verify-email")
async def verify_email(data: EmailVerify):
    verification = await db.email_verifications.find_one({"email": data.email})
    
    if not verification:
        raise HTTPException(status_code=400, detail="Código no encontrado")
    
    if datetime.fromisoformat(verification['expires_at']) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="El código ha expirado")
    
    if not verify_password(data.code, verification['code']):
        raise HTTPException(status_code=400, detail="Código incorrecto")
    
    await db.users.update_one(
        {"email": data.email},
        {"$set": {"email_verified_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    await db.email_verifications.delete_one({"email": data.email})
    
    return {"message": "Correo electrónico verificado exitosamente."}

@api_router.post("/auth/resend-verification")
async def resend_verification(data: ForgotPassword):
    user = await db.users.find_one({"email": data.email})
    
    if not user:
        raise HTTPException(status_code=400, detail="Usuario no encontrado")
    
    if user.get('email_verified_at'):
        raise HTTPException(status_code=400, detail="Este correo ya está verificado")
    
    code = generate_code()
    
    await db.email_verifications.update_one(
        {"email": data.email},
        {"$set": {
            "code": hash_password(code),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        }},
        upsert=True
    )
    
    email_body = f"""
    <h2>Código de Verificación - SafeWatch</h2>
    <p>Tu nuevo código de verificación es:</p>
    <h1 style="color: #10b981; font-size: 32px;">{code}</h1>
    <p>Este código expira en 30 minutos.</p>
    """
    await send_email(data.email, "Código de Verificación - SafeWatch", email_body)
    
    return {"message": "Código de verificación reenviado."}

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(data: UserLogin):
    user = await db.users.find_one({"email": data.email})
    
    if not user or not verify_password(data.password, user['password']):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    
    if not user.get('email_verified_at'):
        raise HTTPException(
            status_code=403, 
            detail="Por favor verifica tu correo electrónico antes de iniciar sesión."
        )
    
    token = create_token(user['id'], data.device_name)
    
    await db.devices.update_one(
        {"user_id": user['id'], "name": data.device_name},
        {"$set": {
            "id": str(uuid.uuid4()),
            "user_id": user['id'],
            "name": data.device_name,
            "last_used_at": datetime.now(timezone.utc).isoformat(),
            "ip_address": "unknown"
        }},
        upsert=True
    )
    
    return TokenResponse(
        token=token,
        user=UserResponse(
            id=user['id'],
            name=user['name'],
            email=user['email'],
            phone=user.get('phone'),
            role=user.get('role', 'user'),
            email_verified_at=user.get('email_verified_at')
        ),
        message="Inicio de sesión exitoso."
    )

@api_router.post("/auth/logout")
async def logout(user = Depends(get_current_user)):
    return {"message": "Sesión cerrada exitosamente."}

@api_router.post("/auth/logout-all-devices")
async def logout_all_devices(data: dict, user = Depends(get_current_user)):
    password = data.get('password')
    if not password or not verify_password(password, user['password']):
        raise HTTPException(status_code=400, detail="Contraseña incorrecta")
    
    await db.devices.delete_many({"user_id": user['id']})
    
    return {"message": "Se ha cerrado sesión en todos los dispositivos."}

@api_router.post("/auth/forgot-password")
async def forgot_password(data: ForgotPassword):
    user = await db.users.find_one({"email": data.email})
    
    if user:
        code = generate_code()
        
        await db.password_resets.update_one(
            {"email": data.email},
            {"$set": {
                "code": hash_password(code),
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
            }},
            upsert=True
        )
        
        email_body = f"""
        <h2>Recuperación de Contraseña - SafeWatch</h2>
        <p>Tu código de recuperación es:</p>
        <h1 style="color: #10b981; font-size: 32px;">{code}</h1>
        <p>Este código expira en 15 minutos.</p>
        """
        await send_email(data.email, "Recuperación de Contraseña - SafeWatch", email_body)
    
    return {"message": "Si el correo existe, recibirás un código de recuperación."}

@api_router.post("/auth/verify-reset-code")
async def verify_reset_code(data: EmailVerify):
    reset = await db.password_resets.find_one({"email": data.email})
    
    if not reset:
        raise HTTPException(status_code=400, detail="Código no encontrado")
    
    if datetime.fromisoformat(reset['expires_at']) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="El código ha expirado")
    
    if not verify_password(data.code, reset['code']):
        raise HTTPException(status_code=400, detail="Código incorrecto")
    
    return {"message": "Código verificado correctamente.", "valid": True}

@api_router.post("/auth/reset-password")
async def reset_password(data: ResetPassword):
    # Validate new password
    validation = validate_password(data.password)
    if not validation['is_valid']:
        raise HTTPException(status_code=400, detail="La contraseña no cumple los requisitos mínimos")
    
    if data.password != data.password_confirmation:
        raise HTTPException(status_code=400, detail="Las contraseñas no coinciden")
    
    reset = await db.password_resets.find_one({"email": data.email})
    
    if not reset or not verify_password(data.code, reset['code']):
        raise HTTPException(status_code=400, detail="Código inválido")
    
    if datetime.fromisoformat(reset['expires_at']) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="El código ha expirado")
    
    await db.users.update_one(
        {"email": data.email},
        {"$set": {"password": hash_password(data.password)}}
    )
    
    user = await db.users.find_one({"email": data.email})
    if user:
        await db.devices.delete_many({"user_id": user['id']})
    
    await db.password_resets.delete_one({"email": data.email})
    
    return {"message": "Contraseña actualizada exitosamente."}

@api_router.post("/auth/change-password")
async def change_password(data: ChangePassword, user = Depends(get_current_user)):
    if not verify_password(data.current_password, user['password']):
        raise HTTPException(status_code=400, detail="Contraseña actual incorrecta")
    
    # Validate new password
    validation = validate_password(data.password)
    if not validation['is_valid']:
        raise HTTPException(status_code=400, detail="La contraseña no cumple los requisitos mínimos")
    
    if data.password != data.password_confirmation:
        raise HTTPException(status_code=400, detail="Las contraseñas no coinciden")
    
    await db.users.update_one(
        {"id": user['id']},
        {"$set": {"password": hash_password(data.password)}}
    )
    
    await db.devices.delete_many({"user_id": user['id']})
    
    return {"message": "Contraseña actualizada. Se ha cerrado sesión en otros dispositivos."}

@api_router.get("/auth/devices")
async def get_devices(user = Depends(get_current_user)):
    devices = await db.devices.find({"user_id": user['id']}).to_list(100)
    return {"devices": serialize_doc(devices)}

@api_router.delete("/auth/devices/{device_id}")
async def revoke_device(device_id: str, user = Depends(get_current_user)):
    result = await db.devices.delete_one({"id": device_id, "user_id": user['id']})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Dispositivo no encontrado")
    return {"message": "Dispositivo eliminado."}

# ============== USER ROUTES ==============

@api_router.get("/user/profile")
async def get_profile(user = Depends(get_current_user)):
    return {
        "user": {
            "id": user['id'],
            "name": user['name'],
            "email": user['email'],
            "phone": user.get('phone'),
            "role": user.get('role', 'user'),
            "email_verified_at": user.get('email_verified_at'),
            "created_at": user.get('created_at')
        }
    }

@api_router.put("/user/profile")
async def update_profile(data: ProfileUpdate, user = Depends(get_current_user)):
    update_data = {}
    if data.name:
        update_data['name'] = data.name
    if data.phone is not None:
        update_data['phone'] = data.phone
    
    if update_data:
        await db.users.update_one({"id": user['id']}, {"$set": update_data})
    
    updated_user = await db.users.find_one({"id": user['id']})
    return {"message": "Perfil actualizado exitosamente.", "user": serialize_doc(updated_user)}

@api_router.post("/user/accept-consent")
async def accept_data_consent(user = Depends(get_current_user)):
    """Accept data usage consent"""
    await db.users.update_one(
        {"id": user['id']},
        {"$set": {
            "data_consent_accepted": True,
            "data_consent_date": datetime.now(timezone.utc).isoformat()
        }}
    )
    return {"message": "Consentimiento aceptado exitosamente."}

@api_router.get("/user/consent-status")
async def get_consent_status(user = Depends(get_current_user)):
    """Check if user has accepted data consent"""
    user_data = await db.users.find_one({"id": user['id']}, {"_id": 0})
    return {
        "accepted": user_data.get("data_consent_accepted", False),
        "date": user_data.get("data_consent_date")
    }

# ============== CONTACTS ROUTES ==============

@api_router.get("/contacts")
async def get_contacts(user = Depends(get_current_user)):
    contacts = await db.contacts.find({"user_id": user['id']}).to_list(100)
    return {"contacts": serialize_doc(contacts)}

@api_router.post("/contacts")
async def create_contact(data: ContactCreate, user = Depends(get_current_user)):
    contact = {
        "id": str(uuid.uuid4()),
        "user_id": user['id'],
        **data.model_dump(),
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.contacts.insert_one(contact)
    return {"message": "Contacto de emergencia agregado.", "contact": serialize_doc(contact)}

@api_router.put("/contacts/{contact_id}")
async def update_contact(contact_id: str, data: ContactCreate, user = Depends(get_current_user)):
    result = await db.contacts.update_one(
        {"id": contact_id, "user_id": user['id']},
        {"$set": data.model_dump()}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Contacto no encontrado")
    return {"message": "Contacto actualizado."}

@api_router.delete("/contacts/{contact_id}")
async def delete_contact(contact_id: str, user = Depends(get_current_user)):
    result = await db.contacts.delete_one({"id": contact_id, "user_id": user['id']})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Contacto no encontrado")
    return {"message": "Contacto eliminado."}

# ============== ALERTS ROUTES ==============

@api_router.get("/alerts")
async def get_alerts(user = Depends(get_current_user)):
    if user.get('role') == 'admin':
        alerts = await db.alerts.find().sort("created_at", -1).to_list(100)
    elif user.get('role') == 'responder':
        alerts = await db.alerts.find(
            {"status": {"$in": ["active", "assigned"]}}
        ).sort("created_at", -1).to_list(100)
    else:
        alerts = await db.alerts.find(
            {"user_id": user['id']}
        ).sort("created_at", -1).to_list(100)
    
    return {"data": serialize_doc(alerts)}

@api_router.post("/alerts")
async def create_alert(data: AlertCreate, user = Depends(get_current_user)):
    alert = {
        "id": str(uuid.uuid4()),
        "user_id": user['id'],
        "type": data.type,
        "status": "active",
        "location": data.location,
        "description": data.description,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.alerts.insert_one(alert)
    return {"message": "Alerta creada exitosamente.", "alert": serialize_doc(alert)}

@api_router.post("/alerts/{alert_id}/respond")
async def respond_alert(alert_id: str, user = Depends(get_current_user)):
    if user.get('role') not in ['admin', 'responder']:
        raise HTTPException(status_code=403, detail="No autorizado")
    
    result = await db.alerts.update_one(
        {"id": alert_id, "status": "active"},
        {"$set": {"status": "assigned", "responder_id": user['id']}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=400, detail="Alerta no disponible")
    return {"message": "Has sido asignado a esta alerta."}

@api_router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str, user = Depends(get_current_user)):
    if user.get('role') not in ['admin', 'responder']:
        raise HTTPException(status_code=403, detail="No autorizado")
    
    await db.alerts.update_one(
        {"id": alert_id},
        {"$set": {"status": "resolved", "resolved_at": datetime.now(timezone.utc).isoformat()}}
    )
    return {"message": "Alerta resuelta."}

# ============== MONITORING ROUTES ==============

@api_router.get("/monitoring/data")
async def get_monitoring_data(user = Depends(get_current_user)):
    """Get latest monitoring data for user"""
    data = await db.monitoring.find_one(
        {"user_id": user['id']},
        sort=[("timestamp", -1)]
    )
    return {"data": serialize_doc(data)}

@api_router.post("/monitoring/data")
async def save_monitoring_data(data: MonitoringData, user = Depends(get_current_user)):
    """Save monitoring data and check for emergencies"""
    
    # Determine status based on vitals
    status = "normal"
    emergency_type = None
    
    # Check for fall
    if data.fall_detected:
        status = "emergency"
        emergency_type = "fall"
    
    # Check for potential heart attack
    if data.bpm > 140 and data.spo2 < 90 and data.stress > 80:
        status = "emergency"
        emergency_type = "heart_attack"
    elif data.bpm > 120 or data.spo2 < 92 or data.stress > 70:
        status = "alert"
    
    monitoring_doc = {
        "id": str(uuid.uuid4()),
        "user_id": user['id'],
        "bpm": data.bpm,
        "spo2": data.spo2,
        "stress": data.stress,
        "movement": data.movement,
        "fall_detected": data.fall_detected,
        "status": status,
        "location": data.location,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    await db.monitoring.insert_one(monitoring_doc)
    
    # If emergency detected, create alert and notify contacts
    if status == "emergency" and emergency_type:
        alert = {
            "id": str(uuid.uuid4()),
            "user_id": user['id'],
            "type": emergency_type,
            "status": "active",
            "location": data.location or {"lat": 0, "lng": 0},
            "monitoring_data": {
                "bpm": data.bpm,
                "spo2": data.spo2,
                "stress": data.stress
            },
            "description": f"Emergencia detectada automáticamente: {emergency_type}",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.alerts.insert_one(alert)
        
        # Log emergency
        await db.emergency_logs.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": user['id'],
            "type": emergency_type,
            "alert_id": alert['id'],
            "monitoring_data": monitoring_doc,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        # Send notifications
        notified = await send_emergency_notification(
            user, 
            emergency_type, 
            data.location or {"lat": 0, "lng": 0}
        )
        
        return {
            "status": status,
            "emergency_type": emergency_type,
            "alert_created": True,
            "notified_contacts": notified,
            "data": serialize_doc(monitoring_doc)
        }
    
    return {
        "status": status,
        "data": serialize_doc(monitoring_doc)
    }

@api_router.get("/monitoring/history")
async def get_monitoring_history(user = Depends(get_current_user), limit: int = 50):
    """Get monitoring history"""
    history = await db.monitoring.find(
        {"user_id": user['id']}
    ).sort("timestamp", -1).limit(limit).to_list(limit)
    
    return {"history": serialize_doc(history)}

@api_router.post("/emergency/manual")
async def trigger_manual_emergency(data: EmergencyAlert, user = Depends(get_current_user)):
    """Trigger a manual emergency alert"""
    
    alert = {
        "id": str(uuid.uuid4()),
        "user_id": user['id'],
        "type": "manual",
        "status": "active",
        "location": data.location,
        "monitoring_data": data.monitoring_data,
        "description": "Emergencia activada manualmente por el usuario",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.alerts.insert_one(alert)
    
    # Log emergency
    await db.emergency_logs.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user['id'],
        "type": "manual",
        "alert_id": alert['id'],
        "location": data.location,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    # Send notifications
    notified = await send_emergency_notification(user, "manual", data.location)
    
    return {
        "message": "Alerta de emergencia enviada",
        "alert": serialize_doc(alert),
        "notified_contacts": notified
    }

@api_router.get("/emergency/history")
async def get_emergency_history(user = Depends(get_current_user)):
    """Get emergency history"""
    history = await db.emergency_logs.find(
        {"user_id": user['id']}
    ).sort("timestamp", -1).to_list(50)
    
    return {"history": serialize_doc(history)}

# ============== SAFE POINTS (Guadalajara) ==============

SAFE_POINTS_GDL = [
    # Hospitales
    {"id": "h1", "name": "Hospital Civil de Guadalajara", "type": "hospital", "lat": 20.6769, "lng": -103.3476, "phone": "33 3614 5501"},
    {"id": "h2", "name": "Hospital General de Occidente", "type": "hospital", "lat": 20.7014, "lng": -103.4144, "phone": "33 3030 6000"},
    {"id": "h3", "name": "Cruz Verde Guadalajara", "type": "hospital", "lat": 20.6597, "lng": -103.3494, "phone": "33 3614 5252"},
    {"id": "h4", "name": "Hospital Ángeles del Carmen", "type": "hospital", "lat": 20.6814, "lng": -103.3638, "phone": "33 3813 0042"},
    
    # Policía
    {"id": "p1", "name": "Comisaría Central", "type": "police", "lat": 20.6736, "lng": -103.3444, "phone": "911"},
    {"id": "p2", "name": "Policía Municipal Zapopan", "type": "police", "lat": 20.7222, "lng": -103.3844, "phone": "33 3836 3636"},
    {"id": "p3", "name": "Policía Estatal Jalisco", "type": "police", "lat": 20.6889, "lng": -103.3511, "phone": "33 3668 0800"},
    
    # Cruz Roja
    {"id": "cr1", "name": "Cruz Roja Guadalajara Centro", "type": "cruz_roja", "lat": 20.6728, "lng": -103.3369, "phone": "33 3614 5600"},
    {"id": "cr2", "name": "Cruz Roja Zapopan", "type": "cruz_roja", "lat": 20.7097, "lng": -103.3939, "phone": "33 3110 1670"},
    
    # Bomberos
    {"id": "b1", "name": "Bomberos Guadalajara Central", "type": "bomberos", "lat": 20.6753, "lng": -103.3386, "phone": "33 3619 5241"},
    {"id": "b2", "name": "Bomberos Zapopan", "type": "bomberos", "lat": 20.7208, "lng": -103.3928, "phone": "33 3633 1758"},
    
    # Protección Civil
    {"id": "pc1", "name": "Protección Civil Jalisco", "type": "proteccion_civil", "lat": 20.6708, "lng": -103.3644, "phone": "33 3030 5300"},
]

@api_router.get("/safe-points")
async def get_safe_points(lat: float = None, lng: float = None, type: str = None):
    """Get safe points, optionally filtered by type and sorted by distance"""
    points = SAFE_POINTS_GDL.copy()
    
    if type:
        points = [p for p in points if p['type'] == type]
    
    # Calculate distance if user location provided
    if lat and lng:
        import math
        for p in points:
            dlat = p['lat'] - lat
            dlng = p['lng'] - lng
            p['distance'] = math.sqrt(dlat**2 + dlng**2) * 111  # Approximate km
        points.sort(key=lambda x: x['distance'])
    
    return {"safe_points": points}

@api_router.get("/safe-points/nearest")
async def get_nearest_safe_point(lat: float, lng: float, type: str = None):
    """Get the nearest safe point"""
    import math
    
    points = SAFE_POINTS_GDL.copy()
    if type:
        points = [p for p in points if p['type'] == type]
    
    for p in points:
        dlat = p['lat'] - lat
        dlng = p['lng'] - lng
        p['distance'] = math.sqrt(dlat**2 + dlng**2) * 111
    
    points.sort(key=lambda x: x['distance'])
    
    if points:
        return {"nearest": points[0]}
    return {"nearest": None}

# ============== ADMIN ROUTES ==============

@api_router.get("/admin/users")
async def admin_get_users(user = Depends(require_admin)):
    users = await db.users.find().to_list(1000)
    # Remove passwords and _id
    result = []
    for u in users:
        user_data = serialize_doc(u)
        if user_data:
            user_data.pop('password', None)
            result.append(user_data)
    return {"data": result}

@api_router.post("/admin/users")
async def admin_create_user(data: AdminUserCreate, user = Depends(require_admin)):
    existing = await db.users.find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="El correo ya está registrado")
    
    new_user = {
        "id": str(uuid.uuid4()),
        "name": data.name,
        "email": data.email,
        "password": hash_password(data.password),
        "phone": data.phone,
        "role": data.role,
        "email_verified_at": datetime.now(timezone.utc).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(new_user)
    result = serialize_doc(new_user)
    result.pop('password', None)
    return {"message": "Usuario creado exitosamente.", "user": result}

@api_router.put("/admin/users/{user_id}")
async def admin_update_user(user_id: str, data: AdminUserUpdate, admin = Depends(require_admin)):
    update_data = {k: v for k, v in data.model_dump().items() if v is not None}
    if 'password' in update_data and update_data['password']:
        update_data['password'] = hash_password(update_data['password'])
    elif 'password' in update_data:
        del update_data['password']
    
    if update_data:
        await db.users.update_one({"id": user_id}, {"$set": update_data})
    return {"message": "Usuario actualizado."}

@api_router.delete("/admin/users/{user_id}")
async def admin_delete_user(user_id: str, admin = Depends(require_admin)):
    if user_id == admin['id']:
        raise HTTPException(status_code=400, detail="No puedes eliminarte a ti mismo")
    
    await db.users.delete_one({"id": user_id})
    await db.devices.delete_many({"user_id": user_id})
    return {"message": "Usuario eliminado."}

@api_router.get("/admin/roles")
async def admin_get_roles(user = Depends(require_admin)):
    return {"roles": ["admin", "responder", "user"]}

@api_router.get("/admin/stats")
async def admin_get_stats(user = Depends(require_admin)):
    users_total = await db.users.count_documents({})
    users_verified = await db.users.count_documents({"email_verified_at": {"$ne": None}})
    admins = await db.users.count_documents({"role": "admin"})
    responders = await db.users.count_documents({"role": "responder"})
    
    alerts_total = await db.alerts.count_documents({})
    alerts_active = await db.alerts.count_documents({"status": "active"})
    alerts_assigned = await db.alerts.count_documents({"status": "assigned"})
    alerts_resolved = await db.alerts.count_documents({"status": "resolved"})
    
    contacts = await db.contacts.count_documents({})
    emergencies = await db.emergency_logs.count_documents({})
    
    return {
        "stats": {
            "users": {
                "total": users_total,
                "verified": users_verified,
                "unverified": users_total - users_verified,
                "admins": admins,
                "responders": responders
            },
            "alerts": {
                "total": alerts_total,
                "active": alerts_active,
                "assigned": alerts_assigned,
                "resolved": alerts_resolved
            },
            "contacts": contacts,
            "emergencies": emergencies
        }
    }

@api_router.get("/admin/collections")
async def admin_get_collections(user = Depends(require_admin)):
    """Dynamically list ALL collections in the database with document counts"""
    collection_names = await db.list_collection_names()
    collections = []
    for name in sorted(collection_names):
        count = await db[name].count_documents({})
        collections.append({"name": name, "count": count})
    return {"collections": collections}

@api_router.get("/admin/collections/{collection}")
async def admin_get_collection_data(collection: str, page: int = 1, limit: int = 50, user = Depends(require_admin)):
    """Get paginated documents from any collection"""
    collection_names = await db.list_collection_names()
    if collection not in collection_names:
        raise HTTPException(status_code=404, detail=f"Colección '{collection}' no encontrada")
    
    coll = db[collection]
    skip = (page - 1) * limit
    total = await coll.count_documents({})
    data = await coll.find().skip(skip).limit(limit).to_list(limit)
    
    result = serialize_doc(data)
    
    # Mask passwords in users collection
    if collection == 'users':
        for item in result:
            if item and 'password' in item:
                item['password'] = '********'
    
    return {
        "data": result,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit
    }

@api_router.get("/admin/collections/{collection}/{doc_id}")
async def admin_get_document(collection: str, doc_id: str, user = Depends(require_admin)):
    """Get a single document by its 'id' field"""
    collection_names = await db.list_collection_names()
    if collection not in collection_names:
        raise HTTPException(status_code=404, detail=f"Colección '{collection}' no encontrada")
    
    doc = await db[collection].find_one({"id": doc_id})
    if not doc:
        # Try by _id as ObjectId
        try:
            doc = await db[collection].find_one({"_id": ObjectId(doc_id)})
        except:
            pass
    
    if not doc:
        raise HTTPException(status_code=404, detail="Documento no encontrado")
    
    result = serialize_doc(doc)
    if collection == 'users' and result and 'password' in result:
        result['password'] = '********'
    
    return {"document": result}

@api_router.post("/admin/collections/{collection}")
async def admin_create_document(collection: str, data: Dict[str, Any], user = Depends(require_admin)):
    """Create a new document in any collection"""
    protected = ['backups']
    if collection in protected:
        raise HTTPException(status_code=403, detail="Use las rutas dedicadas para esta colección")
    
    # Auto-generate id and timestamps
    if 'id' not in data:
        data['id'] = str(uuid.uuid4())
    if 'created_at' not in data:
        data['created_at'] = datetime.now(timezone.utc).isoformat()
    
    # Hash password if creating a user
    if collection == 'users' and 'password' in data and not data['password'].startswith('$2b$'):
        data['password'] = hash_password(data['password'])
    
    await db[collection].insert_one(data)
    result = serialize_doc(data)
    if collection == 'users' and result and 'password' in result:
        result['password'] = '********'
    
    return {"message": "Documento creado exitosamente.", "document": result}

@api_router.put("/admin/collections/{collection}/{doc_id}")
async def admin_update_document(collection: str, doc_id: str, data: Dict[str, Any], user = Depends(require_admin)):
    """Update a document in any collection"""
    # Remove read-only fields from update
    data.pop('_id', None)
    data.pop('id', None)
    
    # Hash password if updating a user's password
    if collection == 'users' and 'password' in data:
        if data['password'] == '********' or not data['password']:
            del data['password']
        elif not data['password'].startswith('$2b$'):
            data['password'] = hash_password(data['password'])
    
    if not data:
        return {"message": "No hay cambios para aplicar."}
    
    # Try by 'id' field first, then by _id
    result = await db[collection].update_one({"id": doc_id}, {"$set": data})
    if result.matched_count == 0:
        try:
            result = await db[collection].update_one({"_id": ObjectId(doc_id)}, {"$set": data})
        except:
            pass
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Documento no encontrado")
    
    return {"message": "Documento actualizado exitosamente."}

@api_router.delete("/admin/collections/{collection}/{doc_id}")
async def admin_delete_document(collection: str, doc_id: str, user = Depends(require_admin)):
    """Delete a document from any collection"""
    # Prevent deleting yourself
    if collection == 'users' and doc_id == user['id']:
        raise HTTPException(status_code=400, detail="No puedes eliminarte a ti mismo")
    
    # Try by 'id' field first, then by _id
    result = await db[collection].delete_one({"id": doc_id})
    if result.deleted_count == 0:
        try:
            result = await db[collection].delete_one({"_id": ObjectId(doc_id)})
        except:
            pass
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Documento no encontrado")
    
    return {"message": "Documento eliminado exitosamente."}

@api_router.get("/admin/indexes")
async def admin_get_indexes(user = Depends(require_admin)):
    return {
        "indexes": {
            "users": [
                {"field": "email", "type": "unique", "description": "Índice único para búsqueda rápida por email"},
                {"field": "created_at", "type": "descending", "description": "Índice para ordenar usuarios por fecha"}
            ],
            "alerts": [
                {"field": "user_id", "type": "ascending", "description": "Índice para alertas por usuario"},
                {"field": "status", "type": "ascending", "description": "Índice para filtrar por estado"}
            ],
            "monitoring": [
                {"field": "user_id", "type": "ascending", "description": "Índice para datos por usuario"},
                {"field": "timestamp", "type": "descending", "description": "Índice para ordenar por tiempo"}
            ]
        }
    }

@api_router.get("/admin/backups")
async def admin_get_backups(user = Depends(require_admin)):
    backups = await db.backups.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return {"data": serialize_doc(backups)}

@api_router.post("/admin/backups")
async def admin_create_backup(data: BackupCreate, user = Depends(require_admin)):
    """Create a real backup of all collections"""
    try:
        # Get all collections
        collections_to_backup = ['users', 'alerts', 'contacts', 'sessions', 'monitoring', 'emergency_logs', 'safe_points']
        backup_data = {}
        total_docs = 0
        
        for collection_name in collections_to_backup:
            try:
                coll_data = await db[collection_name].find({}, {"_id": 0}).to_list(10000)
                backup_data[collection_name] = serialize_doc(coll_data)
                total_docs += len(coll_data)
            except Exception as e:
                logger.error(f"Error backing up {collection_name}: {e}")
                backup_data[collection_name] = []
        
        # Calculate size (approximate)
        import json
        backup_json = json.dumps(backup_data)
        size_kb = len(backup_json.encode('utf-8')) / 1024
        
        backup = {
            "id": str(uuid.uuid4()),
            "name": data.name,
            "type": data.type,
            "status": "completed",
            "size": int(size_kb),
            "total_documents": total_docs,
            "collections": list(backup_data.keys()),
            "data": backup_data,
            "created_by": user['id'],
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        await db.backups.insert_one(backup)
        
        # Remove data from response (too large)
        backup_response = {k: v for k, v in backup.items() if k != 'data'}
        
        return {
            "message": "Respaldo creado exitosamente.",
            "backup": serialize_doc(backup_response)
        }
    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        raise HTTPException(status_code=500, detail=f"Error al crear respaldo: {str(e)}")

@api_router.get("/admin/backups/{backup_id}/download")
async def admin_download_backup(backup_id: str, user = Depends(require_admin)):
    """Download backup as JSON"""
    from fastapi.responses import StreamingResponse
    import json
    import io
    
    backup = await db.backups.find_one({"id": backup_id}, {"_id": 0})
    if not backup:
        raise HTTPException(status_code=404, detail="Respaldo no encontrado")
    
    # Create JSON file
    backup_json = json.dumps(serialize_doc(backup), indent=2, ensure_ascii=False)
    
    # Create file stream
    file_stream = io.BytesIO(backup_json.encode('utf-8'))
    
    filename = f"safewatch_backup_{backup['name']}_{backup_id[:8]}.json"
    
    return StreamingResponse(
        file_stream,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )

@api_router.post("/admin/backups/{backup_id}/restore")
async def admin_restore_backup(backup_id: str, user = Depends(require_admin)):
    """Restore data from a backup"""
    try:
        backup = await db.backups.find_one({"id": backup_id}, {"_id": 0})
        if not backup:
            raise HTTPException(status_code=404, detail="Respaldo no encontrado")
        
        if 'data' not in backup:
            raise HTTPException(status_code=400, detail="Este respaldo no contiene datos")
        
        backup_data = backup['data']
        restored_collections = []
        
        # Restore each collection
        for collection_name, documents in backup_data.items():
            if not documents:
                continue
                
            try:
                # Clear existing data (DANGEROUS!)
                await db[collection_name].delete_many({})
                
                # Insert backup data
                if documents:
                    await db[collection_name].insert_many(documents)
                
                restored_collections.append(collection_name)
                logger.info(f"Restored {len(documents)} documents to {collection_name}")
            except Exception as e:
                logger.error(f"Error restoring {collection_name}: {e}")
        
        return {
            "message": "Respaldo restaurado exitosamente",
            "restored_collections": restored_collections,
            "total_collections": len(restored_collections)
        }
    except Exception as e:
        logger.error(f"Error restoring backup: {e}")
        raise HTTPException(status_code=500, detail=f"Error al restaurar: {str(e)}")

@api_router.get("/admin/backups/latest/info")
async def admin_get_latest_backup(user = Depends(require_admin)):
    """Get info about the latest backup"""
    latest = await db.backups.find_one(
        {},
        {"_id": 0, "data": 0},  # Exclude data field
        sort=[("created_at", -1)]
    )
    
    if not latest:
        return {"message": "No hay respaldos disponibles", "backup": None}
    
    return {"backup": serialize_doc(latest)}

@api_router.delete("/admin/backups/{backup_id}")
async def admin_delete_backup(backup_id: str, user = Depends(require_admin)):
    result = await db.backups.delete_one({"id": backup_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Respaldo no encontrado")
    return {"message": "Respaldo eliminado."}

@api_router.get("/admin/db-status")
async def admin_db_status(user = Depends(require_admin)):
    """Get database connection status and statistics"""
    try:
        # Test connection
        await client.admin.command('ping')
        
        # Get database stats
        stats = await db.command('dbStats')
        
        # Count documents in each collection
        collections_info = []
        collection_names = await db.list_collection_names()
        
        for coll_name in collection_names:
            count = await db[coll_name].count_documents({})
            collections_info.append({
                "name": coll_name,
                "count": count
            })
        
        return {
            "status": "connected",
            "database": db_name,
            "mongo_url": "MongoDB Atlas (" + (mongo_url.split('@')[1].split('/')[0] if '@' in mongo_url else "unknown") + ")",
            "collections": collections_info,
            "total_size_mb": round(stats.get('dataSize', 0) / (1024 * 1024), 2),
            "total_documents": sum(c['count'] for c in collections_info)
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "database": db_name
        }

# ============== SEED DATA ==============

@api_router.post("/seed")
async def seed_database():
    admin_exists = await db.users.find_one({"role": "admin"})
    
    if not admin_exists:
        admin = {
            "id": str(uuid.uuid4()),
            "name": "Administrador",
            "email": "admin@safewatch.com",
            "password": hash_password("Admin123!"),
            "role": "admin",
            "email_verified_at": datetime.now(timezone.utc).isoformat(),
            "data_consent_accepted": True,
            "data_consent_date": datetime.now(timezone.utc).isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.users.insert_one(admin)
        
        responder = {
            "id": str(uuid.uuid4()),
            "name": "Respondedor",
            "email": "responder@safewatch.com",
            "password": hash_password("Responder123!"),
            "role": "responder",
            "email_verified_at": datetime.now(timezone.utc).isoformat(),
            "data_consent_accepted": True,
            "data_consent_date": datetime.now(timezone.utc).isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.users.insert_one(responder)
        
        user = {
            "id": str(uuid.uuid4()),
            "name": "Usuario de Prueba",
            "email": "usuario@safewatch.com",
            "password": hash_password("Usuario123!"),
            "phone": "+52 123 456 7890",
            "role": "user",
            "email_verified_at": datetime.now(timezone.utc).isoformat(),
            "data_consent_accepted": False,  # For testing consent modal
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.users.insert_one(user)
        
        return {"message": "Base de datos inicializada con usuarios de prueba."}
    
    return {"message": "La base de datos ya tiene datos."}

# Include router and configure app
app.include_router(api_router)

# Health check endpoint (outside /api prefix for Render)
@app.get("/health")
async def health_check():
    try:
        await client.admin.command('ping')
        return {"status": "ok", "database": "connected"}
    except:
        return {"status": "ok", "database": "disconnected"}

@app.get("/api/health")
async def api_health_check():
    try:
        await client.admin.command('ping')
        return {"status": "ok", "database": "connected"}
    except:
        return {"status": "ok", "database": "disconnected"}

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    try:
        await client.admin.command('ping')
        logger.info("MongoDB connection VERIFIED - database: %s", db_name)
    except Exception as e:
        logger.error("MongoDB connection failed: %s", str(e)[:200])
        raise RuntimeError(f"No se pudo conectar a MongoDB: {str(e)[:200]}")
    
    # Seed admin if needed
    admin_exists = await db.users.find_one({"role": "admin"})
    if not admin_exists:
        logger.info("Seeding database with initial users...")
        await seed_database()

@app.on_event("shutdown")
async def shutdown():
    client.close()
