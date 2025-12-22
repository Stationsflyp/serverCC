from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import sqlite3
import hashlib
import uuid
import datetime
import os
import secrets
import requests
import json
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

SETUP_KEY = os.getenv("SETUP_KEY", "")

# ----------------- MODELS -----------------
class UserCreate(BaseModel):
    username: str = None
    password: str = None
    setup_key: str = None

class LoginRequest(BaseModel):
    username: str = None
    password: str = None
    hwid: str = "WEB_CLIENT"
    owner_id: str = None

class ValidateRequest(BaseModel):
    username: str = None
    password: str = None
    hwid: str = "WEB_CLIENT"
    owner_id: str = None

class LicenseCheck(BaseModel):
    key: str = None
    hwid: str = "WEB_CLIENT"

class VersionCheck(BaseModel):
    version: str
    owner_id: str = None

class VersionUpdate(BaseModel):
    version: str
    owner_id: str = None
    secret: str = None

class ClientCreateUser(BaseModel):
    owner_id: str
    secret: str = None
    username: str = None
    password: str = None

class ClientRequest(BaseModel):
    owner_id: str
    secret: str = None

class ProfileVerify(BaseModel):
    owner_id: str
    secret: str
    app_name: str

class AdminAuthRequest(BaseModel):
    owner_id: str
    secret: str

class AdminActionRequest(BaseModel):
    owner_id: str
    secret: str
    action_data: dict = None

class AdminIdRequest(BaseModel):
    owner_id: str
    secret: str
    id: int = None

class AdminBanRequest(BaseModel):
    owner_id: str
    secret: str
    ip: str = None
    hwid: str = None
    reason: str = None

class AdminCreateUserRequest(BaseModel):
    owner_id: str
    secret: str
    username: str = None
    password: str = None

class DiscordCallbackRequest(BaseModel):
    code: str
    redirect_uri: str = None

class RegisterWithLicenseRequest(BaseModel):
    license_key: str
    username: str
    password: str
    hwid: str = "WEB_CLIENT"

class GenerateLicenseRequest(BaseModel):
    owner_id: str
    secret: str
    days: int = 30
    is_lifetime: bool = False
    notes: str = ""

# ----------------- CORS -----------------
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://authshield\.netlify\.app|http://localhost.*|http://127\.0\.0\.1.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- CHAT -----------------
class ChatMessage(BaseModel):
    username: str
    message: str
    avatar_url: str = None
    email: str = None

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

# ----------------- DB -----------------
DB_FILE = "oxcy_auth.db"

def db():
    conn = sqlite3.connect(DB_FILE, timeout=30.0, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

# ----------------- INIT DB -----------------
def init_db():
    con = db()
    cur = con.cursor()

    try:
        cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
        res = cur.fetchone()
        if res and "UNIQUE(username, owner_id)" not in res[0]:
            print("Migrating users table schema...")
            cur.execute("ALTER TABLE users RENAME TO users_old")
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    hwid TEXT,
                    ip TEXT,
                    last_login TEXT,
                    blocked INTEGER DEFAULT 0,
                    app_name TEXT,
                    owner_id TEXT,
                    secret TEXT,
                    is_admin INTEGER DEFAULT 0,
                    hwid_locked INTEGER DEFAULT 0,
                    hwid_reset_requested INTEGER DEFAULT 0,
                    version TEXT DEFAULT '1.1',
                    UNIQUE(username, owner_id)
                )
            """)
            
            cur.execute("PRAGMA table_info(users_old)")
            columns_old = [r[1] for r in cur.fetchall()]
            
            cur.execute("PRAGMA table_info(users)")
            columns_new = [r[1] for r in cur.fetchall()]
            
            common_columns = [c for c in columns_old if c in columns_new]
            cols_str = ", ".join(common_columns)
            
            cur.execute(f"INSERT INTO users ({cols_str}) SELECT {cols_str} FROM users_old")
            cur.execute("DROP TABLE users_old")
            con.commit()
            print("Migration complete.")
    except Exception as e:
        print(f"Migration failed: {e}")

    try:
        cur.execute("ALTER TABLE users ADD COLUMN version TEXT DEFAULT '1.1'")
    except:
        pass
    
    try:
        cur.execute("ALTER TABLE users ADD COLUMN force_logout INTEGER DEFAULT 0")
    except:
        pass

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            hwid TEXT,
            ip TEXT,
            last_login TEXT,
            blocked INTEGER DEFAULT 0,
            app_name TEXT,
            owner_id TEXT,
            secret TEXT,
            is_admin INTEGER DEFAULT 0,
            hwid_locked INTEGER DEFAULT 0,
            hwid_reset_requested INTEGER DEFAULT 0,
            force_logout INTEGER DEFAULT 0,
            version TEXT DEFAULT '1.1',
            UNIQUE(username, owner_id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            hwid TEXT,
            expires TEXT NOT NULL,
            owner_id TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS banned_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            hwid TEXT,
            reason TEXT,
            banned_at TEXT NOT NULL,
            UNIQUE(ip, hwid)
        )
    """)

    try:
        cur.execute("ALTER TABLE users ADD COLUMN ip TEXT")
    except:
        pass

    try:
        cur.execute("ALTER TABLE banned_ips ADD COLUMN hwid TEXT")
    except:
        pass

    try:
        cur.execute("ALTER TABLE users ADD COLUMN blocked INTEGER DEFAULT 0")
    except:
        pass

    try:
        cur.execute("ALTER TABLE users ADD COLUMN app_name TEXT")
    except:
        pass

    try:
        cur.execute("ALTER TABLE users ADD COLUMN owner_id TEXT")
    except:
        pass

    try:
        cur.execute("ALTER TABLE users ADD COLUMN secret TEXT")
    except:
        pass

    try:
        cur.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    except:
        pass

    try:
        cur.execute("PRAGMA table_info(licenses)")
        cols = [row[1] for row in cur.fetchall()]
        if "license_key" not in cols:
            print("Reconstruyendo tabla licenses...")
            cur.execute("DROP TABLE IF EXISTS licenses")
            cur.execute("""
                CREATE TABLE licenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_key TEXT UNIQUE NOT NULL,
                    hwid TEXT,
                    expires TEXT NOT NULL,
                    owner_id TEXT,
                    notes TEXT
                )
            """)
            print("Tabla licenses recreada")
    except:
        pass
    
    try:
        cur.execute("ALTER TABLE licenses ADD COLUMN owner_id TEXT")
    except:
        pass
    
    try:
        cur.execute("ALTER TABLE licenses ADD COLUMN notes TEXT")
    except:
        pass

    try:
        cur.execute("ALTER TABLE users ADD COLUMN hwid_locked INTEGER DEFAULT 0")
    except:
        pass

    try:
        cur.execute("ALTER TABLE users ADD COLUMN hwid_reset_requested INTEGER DEFAULT 0")
    except:
        pass

    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            owner_id TEXT,
            avatar_url TEXT,
            email TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id TEXT UNIQUE NOT NULL,
            tier TEXT DEFAULT 'free',
            status TEXT DEFAULT 'inactive',
            payment_id TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS team_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id TEXT NOT NULL,
            invited_email TEXT NOT NULL,
            username TEXT,
            role TEXT DEFAULT 'user',
            permissions TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            UNIQUE(owner_id, invited_email)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS usage_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id TEXT NOT NULL,
            exe_name TEXT,
            hwid TEXT,
            country TEXT,
            ip TEXT,
            timestamp TEXT NOT NULL,
            action TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS webhook_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id TEXT UNIQUE NOT NULL,
            discord_webhook_url TEXT,
            enabled INTEGER DEFAULT 0,
            log_anticracks INTEGER DEFAULT 1,
            log_exe_launch INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            ip TEXT NOT NULL,
            latitude REAL,
            longitude REAL,
            country TEXT,
            city TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cur.execute("SELECT COUNT(*) FROM config WHERE key='app_version'")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO config (key, value) VALUES ('app_version', '1.1')") 
        
        try:
            cur.execute("UPDATE users SET is_admin=1 WHERE owner_id IS NULL")
        except:
            pass

    con.close()

init_db()

# ----------------- UTILS -----------------
def sha256(x: str):
    salt = secrets.token_hex(32)
    hash_obj = hashlib.sha256((salt + x).encode())
    return f"{salt}${hash_obj.hexdigest()}"

def verify_password(stored_hash: str, password: str):
    try:
        if "$" not in stored_hash:
            return hashlib.sha256(password.encode()).hexdigest() == stored_hash
        salt, hash_val = stored_hash.split("$", 1)
        return hashlib.sha256((salt + password).encode()).hexdigest() == hash_val
    except:
        return False

def gen_session():
    return secrets.token_urlsafe(32)

def gen_license():
    return "OXCY-" + secrets.token_hex(8).upper()

def gen_owner_id():
    return secrets.token_hex(5).upper()

def gen_secret():
    return secrets.token_urlsafe(32)

def gen_app_name():
    return "App_" + secrets.token_hex(6).upper()

def validate_username(username: str) -> bool:
    if not username or len(username) < 3 or len(username) > 50:
        return False
    return username.isalnum() or "_" in username or "-" in username

def validate_password(password: str) -> bool:
    return password and len(password) >= 8 and len(password) <= 256

def sanitize_input(value: str, max_length: int = 256) -> str:
    if not isinstance(value, str):
        return ""
    return value[:max_length].strip()

# Request counters for rate limiting (simple in-memory)
request_counts = {}

def check_rate_limit(key: str, max_requests: int = 10, window: int = 60) -> bool:
    import time
    now = time.time()
    if key not in request_counts:
        request_counts[key] = []
    request_counts[key] = [ts for ts in request_counts[key] if now - ts < window]
    if len(request_counts[key]) >= max_requests:
        return False
    request_counts[key].append(now)
    return True

def verify_admin(owner_id: str, secret: str) -> tuple[bool, dict]:
    if not owner_id or not secret or len(owner_id) > 50 or len(secret) > 256:
        return False, {"success": False, "message": "Credenciales inválidas"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute(
            "SELECT id, secret, is_admin FROM users WHERE owner_id=? LIMIT 1",
            (owner_id,)
        )
        user = cur.fetchone()
        
        if not user:
            return False, {"success": False, "message": "Perfil no encontrado"}
        
        if user[1] != secret:
            return False, {"success": False, "message": "Secret inválido"}
        
        if user[2] != 1:
            return False, {"success": False, "message": "Acceso denegado: no eres admin"}
        
        return True, {"user_id": user[0]}
    except Exception as e:
        return False, {"success": False, "message": "Error en autenticación"}
    finally:
        if con:
            con.close()

def verify_client(owner_id: str, secret: str) -> tuple[bool, dict]:
    if not owner_id or not secret or len(owner_id) > 50 or len(secret) > 256:
        return False, {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute(
            "SELECT id, secret FROM users WHERE owner_id=? LIMIT 1",
            (owner_id,)
        )
        user = cur.fetchone()
        
        if not user:
            return False, {"success": False, "message": "Acceso denegado"}
        
        if user[1] != secret:
            return False, {"success": False, "message": "Acceso denegado"}
        
        return True, {"user_id": user[0]}
    except Exception as e:
        return False, {"success": False, "message": "Acceso denegado"}
    finally:
        if con:
            con.close()

# ----------------- INIT (EXE) -----------------
@app.post("/api/init")
def api_init():
    return {
        "success": True,
        "sessionid": gen_session(),
        "message": "Initialized"
    }

# ----------------- ADMIN -----------------
@app.post("/api/register")
def register(data: UserCreate):
    if SETUP_KEY and data.setup_key != SETUP_KEY:
        raise HTTPException(403, "Acceso denegado")
    
    if not check_rate_limit("register", max_requests=5, window=300):
        raise HTTPException(429, "Demasiados intentos de registro. Intenta más tarde.")
    
    if not validate_username(data.username):
        raise HTTPException(400, "Usuario inválido. Mín 3 caracteres, máx 50, solo alfanumérico, _ y -")
    
    if not validate_password(data.password):
        raise HTTPException(400, "Contraseña débil. Mín 8 caracteres, máx 256")
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        app_name = gen_app_name()
        owner_id = gen_owner_id()
        secret = gen_secret()
        
        cur.execute(
            "INSERT INTO users (username, password, app_name, owner_id, secret, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
            (data.username, sha256(data.password), app_name, owner_id, secret, 1)
        )
        con.commit()
        return {
            "success": True,
            "message": "Usuario registrado exitosamente",
            "owner_id": owner_id,
            "secret": secret,
            "app_name": app_name
        }
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Este usuario ya existe")
    except Exception:
        raise HTTPException(500, "Error al registrar usuario")

@app.post("/api/register_with_license")
def register_with_license(data: RegisterWithLicenseRequest):
    if not validate_username(data.username):
        raise HTTPException(400, "Usuario inválido")
    
    if not validate_password(data.password):
        raise HTTPException(400, "Contraseña débil")
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute(
            "SELECT id, hwid, expires, owner_id FROM licenses WHERE license_key=?",
            (data.license_key,)
        )
        lic = cur.fetchone()
        
        if not lic:
            raise HTTPException(400, "Licencia inválida")
        
        if datetime.datetime.fromisoformat(lic[2]) < datetime.datetime.utcnow():
            raise HTTPException(400, "Licencia expirada")
        
        if lic[1] is None:
            cur.execute("UPDATE licenses SET hwid=? WHERE id=?", (data.hwid, lic[0]))
        elif lic[1] != data.hwid:
            raise HTTPException(400, "HWID de licencia no coincide")
        
        owner_id = lic[3]
        cur.execute(
            "SELECT secret FROM users WHERE owner_id=? LIMIT 1",
            (owner_id,)
        )
        admin = cur.fetchone()
        
        if not admin:
            raise HTTPException(400, "Licencia no válida")
        
        cur.execute(
            "INSERT INTO users (username, password, owner_id, hwid) VALUES (?, ?, ?, ?)",
            (data.username, sha256(data.password), owner_id, data.hwid)
        )
        con.commit()
        
        return {
            "success": True,
            "message": "Usuario registrado con licencia",
            "owner_id": owner_id,
            "secret": admin[0]
        }
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Usuario ya existe")
    except Exception as e:
        raise HTTPException(500, f"Error: {str(e)}")
    finally:
        if con:
            con.close()

@app.post("/api/admin/create_user")
def create_user(data: AdminCreateUserRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    if not data.username or not data.password:
        raise HTTPException(400, "Username and password are required")
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        app_name = gen_app_name()
        owner_id = gen_owner_id()
        secret = gen_secret()
        
        cur.execute(
            "INSERT INTO users (username, password, app_name, owner_id, secret, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
            (data.username, sha256(data.password), app_name, owner_id, secret, 0)
        )
        con.commit()
        return {"success": True, "message": "User created", "owner_id": owner_id, "app_name": app_name}
    except sqlite3.IntegrityError:
        raise HTTPException(400, "User already exists")
    except Exception as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        if con:
            con.close()

@app.post("/api/admin/generate")
def generate_license(data: GenerateLicenseRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    key = gen_license()
    
    if data.is_lifetime:
        exp = (datetime.datetime.utcnow() + datetime.timedelta(days=36500)).isoformat()
    else:
        exp = (datetime.datetime.utcnow() + datetime.timedelta(days=data.days)).isoformat()

    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "INSERT INTO licenses (license_key, expires, owner_id, notes) VALUES (?, ?, ?, ?)",
            (key, exp, data.owner_id, data.notes)
        )
        con.commit()
        return {
            "success": True,
            "key": key,
            "expires": exp,
            "is_lifetime": data.is_lifetime
        }
    except Exception as e:
        print(f"[AdminLicense] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        if con:
            con.close()

# --------- ADMIN LIST USERS ----------
@app.get("/api/admin/users")
def list_users(owner_id: str = None, secret: str = None):
    is_valid, auth_result = verify_admin(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        try:
            cur.execute("SELECT id, username, hwid, ip, last_login, blocked FROM users")
        except:
            cur.execute("SELECT id, username, hwid, NULL as ip, last_login, 0 as blocked FROM users")
        
        rows = cur.fetchall()

        users = []
        for r in rows:
            users.append({
                "id": r[0],
                "username": r[1],
                "hwid": r[2],
                "ip": r[3],
                "last_login": r[4],
                "blocked": r[5]
            })

        return {"success": True, "users": users}
    except Exception as e:
        raise HTTPException(500, "Error en base de datos")
    finally:
        if con:
            con.close()

# --------- ADMIN LIST LICENSES ----------
@app.get("/api/admin/licenses")
def list_licenses(owner_id: str = None, secret: str = None):
    is_valid, auth_result = verify_admin(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT id, license_key, hwid, expires FROM licenses")
        rows = cur.fetchall()

        licenses = []
        for r in rows:
            licenses.append({
                "id": r[0],
                "license_key": r[1],
                "hwid": r[2],
                "expires": r[3]
            })

        return {"success": True, "licenses": licenses}
    finally:
        if con:
            con.close()

# --------- CLIENT LIST USERS (por owner_id) ----------
@app.get("/api/client/users/{owner_id}")
def client_list_users(owner_id: str, secret: str = None):
    is_valid, auth_result = verify_client(owner_id, secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "SELECT id, username, hwid, ip, last_login, blocked, hwid_reset_requested FROM users WHERE owner_id=? ORDER BY id DESC",
            (owner_id,)
        )
        rows = cur.fetchall()

        users = []
        for r in rows:
            users.append({
                "id": r[0],
                "username": r[1],
                "hwid": r[2],
                "ip": r[3],
                "last_login": r[4],
                "blocked": r[5],
                "hwid_reset_requested": r[6]
            })

        return {"success": True, "users": users}
    except Exception as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        if con:
            con.close()

@app.post("/api/dashboard/profile")
def dashboard_profile(data: ProfileVerify):
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute("SELECT id, owner_id, secret, app_name FROM users WHERE app_name=? LIMIT 1", (data.app_name,))
        user = cur.fetchone()
        
        if user:
            return {
                "success": True,
                "owner_id": user[1],
                "secret": user[2],
                "app_name": user[3]
            }
        
        owner_id = gen_owner_id()
        secret = gen_secret()
        temp_password = sha256(secrets.token_urlsafe(32))
        
        cur.execute(
            "INSERT INTO users (username, password, app_name, owner_id, secret, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
            (owner_id, temp_password, data.app_name, owner_id, secret, 1)
        )
        con.commit()
        
        return {
            "success": True,
            "owner_id": owner_id,
            "secret": secret,
            "app_name": data.app_name
        }
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/discord/callback")
def discord_callback(data: DiscordCallbackRequest):
    con = None
    try:
        print(f"[Discord OAuth] Starting callback with code: {data.code[:20]}...")
        
        DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
        DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
        REDIRECT_URI = data.redirect_uri or os.getenv("DISCORD_REDIRECT_URI", "")
        
        print(f"[Discord OAuth] Client ID: {DISCORD_CLIENT_ID[:20] if DISCORD_CLIENT_ID else 'NOT SET'}...")
        print(f"[Discord OAuth] Client Secret: {'SET' if DISCORD_CLIENT_SECRET else 'NOT SET'}")
        print(f"[Discord OAuth] Redirect URI: {REDIRECT_URI}")
        
        if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
            print("[Discord OAuth] ERROR: Credentials not configured")
            return {"success": False, "message": "Discord credentials not configured"}
        
        token_url = "https://discord.com/api/v10/oauth2/token"
        payload = {
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": data.code,
            "redirect_uri": REDIRECT_URI
        }
        
        print(f"[Discord OAuth] Requesting token from Discord...")
        print(f"[Discord OAuth] Payload: {payload}")
        response = requests.post(token_url, data=payload)
        print(f"[Discord OAuth] Response status: {response.status_code}")
        print(f"[Discord OAuth] Response headers: {response.headers}")
        token_data = response.json()
        print(f"[Discord OAuth] Token response: {token_data}")
        
        if "error" in token_data:
            error_msg = f"Discord error: {token_data.get('error_description', token_data.get('message', 'Unknown error'))}"
            print(f"[Discord OAuth] ERROR: {error_msg}")
            return {"success": False, "message": error_msg}
        
        access_token = token_data.get("access_token")
        if not access_token:
            error_msg = f"No access token. Response: {token_data}"
            print(f"[Discord OAuth] ERROR: {error_msg}")
            return {"success": False, "message": error_msg}
        
        print(f"[Discord OAuth] Got access token, fetching user info...")
        user_url = "https://discord.com/api/v10/users/@me"
        headers = {"Authorization": f"Bearer {access_token}"}
        user_response = requests.get(user_url, headers=headers)
        user_data = user_response.json()
        print(f"[Discord OAuth] User data: {user_data}")
        
        if "error" in user_data:
            error_msg = f"Failed to fetch user info: {user_data.get('message', 'Unknown error')}"
            print(f"[Discord OAuth] ERROR: {error_msg}")
            return {"success": False, "message": error_msg}
        
        discord_id = user_data.get("id")
        discord_username = user_data.get("username")
        discord_email = user_data.get("email")
        
        print(f"[Discord OAuth] User: {discord_username} ({discord_id}), Email: {discord_email}")
        
        WHITELIST_DISCORD_IDS = os.getenv("WHITELIST_DISCORD_IDS", "").strip()
        if WHITELIST_DISCORD_IDS:
            whitelist = [uid.strip() for uid in WHITELIST_DISCORD_IDS.split(",")]
            discord_id_str = str(discord_id)
            if discord_id_str not in whitelist:
                error_msg = f"❌ Tu Discord ID ({discord_id_str}) no está autorizado para acceder a esta aplicación. Solo usuarios seleccionados pueden ingresar."
                print(f"[Discord OAuth] Whitelist check failed for Discord ID: {discord_id_str}")
                return {"success": False, "message": error_msg}
            print(f"[Discord OAuth] Discord ID {discord_id_str} is whitelisted ✓")
        
        avatar_hash = user_data.get("avatar")
        avatar_url = f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.png" if avatar_hash else None
        
        con = db()
        cur = con.cursor()
        
        cur.execute("SELECT owner_id, secret, app_name FROM users WHERE username=? LIMIT 1", (f"discord_{discord_id}",))
        user = cur.fetchone()
        
        if user:
            print(f"[Discord OAuth] User already exists, returning credentials")
            return {
                "success": True,
                "owner_id": user[0],
                "secret": user[1],
                "app_name": user[2],
                "avatar": avatar_url,
                "email": discord_email
            }
        
        print(f"[Discord OAuth] Creating new user...")
        owner_id = gen_owner_id()
        secret = gen_secret()
        app_name = f"Discord_{discord_username}"
        temp_password = sha256(secrets.token_urlsafe(32))
        
        cur.execute(
            "INSERT INTO users (username, password, app_name, owner_id, secret, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
            (f"discord_{discord_id}", temp_password, app_name, owner_id, secret, 1)
        )
        con.commit()
        
        print(f"[Discord OAuth] User created: {app_name}")
        return {
            "success": True,
            "owner_id": owner_id,
            "secret": secret,
            "app_name": app_name,
            "avatar": avatar_url,
            "email": discord_email
        }
    except Exception as e:
        print(f"[Discord OAuth] EXCEPTION: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"success": False, "message": f"Error: {str(e)}"}
    finally:
        if con:
            con.close()

@app.post("/api/profile/verify")
def verify_profile(data: ProfileVerify):
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "SELECT secret, app_name FROM users WHERE owner_id=? LIMIT 1",
            (data.owner_id,)
        )
        user = cur.fetchone()
        
        if not user:
            return "0"
        
        if user[0] != data.secret:
            return "0"
        
        if user[1] != data.app_name:
            return "0"
        
        return "1"
    except:
        return "0"
    finally:
        if con:
            con.close()

# --------- ADMIN RESET HWID ----------
@app.post("/api/admin/reset_hwid/{user_id}")
def reset_hwid(user_id: int, data: AdminAuthRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute(
            "UPDATE users SET hwid=NULL, hwid_locked=0, hwid_reset_requested=0 WHERE id=?",
            (user_id,)
        )
        con.commit()
        return {"success": True, "message": "HWID reseteado"}
    except Exception:
        raise HTTPException(500, "Error al resetear HWID")
    finally:
        if con:
            con.close()

# --------- ADMIN DELETE USER ----------
@app.post("/api/admin/delete_user/{user_id}")
def delete_user(user_id: int, data: AdminAuthRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
        return {"success": True, "message": "Usuario eliminado"}
    except Exception as e:
        raise HTTPException(500, f"Error: {str(e)}")
    finally:
        if con:
            con.close()

# --------- ADMIN DELETE LICENSE ----------
@app.post("/api/admin/delete_license/{license_id}")
def delete_license(license_id: int, data: AdminAuthRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("DELETE FROM licenses WHERE id=?", (license_id,))
        return {"success": True, "message": "Licencia eliminada"}
    except Exception:
        raise HTTPException(500, "Error al eliminar licencia")
    finally:
        if con:
            con.close()

# --------- ADMIN BLOCK/UNBLOCK USER ----------
@app.post("/api/admin/block_user/{user_id}")
def block_user(user_id: int, data: AdminAuthRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("UPDATE users SET blocked=1 WHERE id=?", (user_id,))
        return {"success": True, "message": "Usuario bloqueado"}
    except Exception:
        raise HTTPException(500, "Error al bloquear usuario")
    finally:
        if con:
            con.close()

@app.post("/api/admin/unblock_user/{user_id}")
def unblock_user(user_id: int, data: AdminAuthRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("UPDATE users SET blocked=0 WHERE id=?", (user_id,))
        return {"success": True, "message": "Usuario desbloqueado"}
    except Exception:
        raise HTTPException(500, "Error al desbloquear usuario")
    finally:
        if con:
            con.close()

# --------- ADMIN BAN IP/HWID ----------
class BanRequest(BaseModel):
    owner_id: str
    secret: str
    ip: str = None
    hwid: str = None
    reason: str = "Sin razón"

@app.post("/api/admin/ban_ip")
def ban_ip(data: BanRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "INSERT INTO banned_ips (ip, hwid, reason, date) VALUES (?, ?, ?, ?)",
            (data.ip, None, data.reason, datetime.datetime.utcnow().isoformat())
        )
        return {"success": True, "message": "IP baneada"}
    except sqlite3.IntegrityError:
        raise HTTPException(400, "IP ya está baneada")
    except Exception:
        raise HTTPException(500, "Error al banear IP")
    finally:
        if con:
            con.close()

@app.post("/api/admin/ban_hwid")
def ban_hwid(data: BanRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "INSERT INTO banned_ips (ip, hwid, reason, date) VALUES (?, ?, ?, ?)",
            (None, data.hwid, data.reason, datetime.datetime.utcnow().isoformat())
        )
        return {"success": True, "message": "Hardware baneado"}
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Hardware ya está baneado")
    except Exception:
        raise HTTPException(500, "Error al banear hardware")
    finally:
        if con:
            con.close()

# --------- ADMIN LIST BANNED IPS/HWIDS ----------
@app.get("/api/admin/banned_ips")
def list_banned_ips(owner_id: str = None, secret: str = None):
    is_valid, auth_result = verify_admin(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT id, ip, hwid, reason, date FROM banned_ips")
        rows = cur.fetchall()

        banned_ips = []
        for r in rows:
            banned_ips.append({
                "id": r[0],
                "ip": r[1],
                "hwid": r[2],
                "reason": r[3],
                "banned_at": r[4]
            })

        return {"success": True, "banned_ips": banned_ips}
    finally:
        if con:
            con.close()

@app.post("/api/client/unban_ip/{ban_id}")
def client_unban_ip(ban_id: int, data: ClientRequest):
    is_valid, auth_result = verify_client(data.owner_id, data.secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT hwid FROM banned_ips WHERE id=?", (ban_id,))
        result = cur.fetchone()
        if result:
            hwid_to_unban = result[0]
            cur.execute("DELETE FROM banned_ips WHERE id=?", (ban_id,))
            if hwid_to_unban:
                cur.execute("UPDATE licenses SET hwid=NULL WHERE hwid=?", (hwid_to_unban,))
            con.commit()
        return {"success": True, "message": "Desbaneado"}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()



# --------- ADMIN UNBAN IP ----------
@app.post("/api/admin/unban_ip/{ban_id}")
def unban_ip(ban_id: int, data: AdminAuthRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT hwid FROM banned_ips WHERE id=?", (ban_id,))
        result = cur.fetchone()
        if result:
            hwid_to_unban = result[0]
            cur.execute("DELETE FROM banned_ips WHERE id=?", (ban_id,))
            if hwid_to_unban:
                cur.execute("UPDATE licenses SET hwid=NULL WHERE hwid=?", (hwid_to_unban,))
            con.commit()
        return {"success": True, "message": "Baneado removido"}
    except Exception:
        raise HTTPException(500, "Error al desbanear")
    finally:
        if con:
            con.close()

# --------- ADMIN LIST HWID RESET REQUESTS ----------
@app.get("/api/admin/hwid_resets")
def list_hwid_resets(owner_id: str = None, secret: str = None):
    is_valid, auth_result = verify_admin(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT id, username, hwid, hwid_locked, hwid_reset_requested FROM users WHERE hwid_reset_requested=1 AND hwid_locked=1")
        rows = cur.fetchall()
        
        resets = []
        for r in rows:
            resets.append({
                "id": r[0],
                "username": r[1],
                "old_hwid": r[2],
                "hwid_locked": r[3],
                "reset_requested": r[4]
            })
        
        return {"success": True, "resets": resets}
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        if con:
            con.close()

# --------- ADMIN APPROVE HWID RESET ----------
@app.post("/api/admin/approve_hwid_reset/{user_id}")
def approve_hwid_reset(user_id: int, data: AdminAuthRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "UPDATE users SET hwid=NULL, hwid_locked=0, hwid_reset_requested=0 WHERE id=?",
            (user_id,)
        )
        con.commit()
        return {"success": True, "message": "Reset HWID aprobado"}
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        if con:
            con.close()

# --------- ADMIN DENY HWID RESET ----------
@app.post("/api/admin/deny_hwid_reset/{user_id}")
def deny_hwid_reset(user_id: int, data: AdminAuthRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "UPDATE users SET hwid_locked=0, hwid_reset_requested=0 WHERE id=?",
            (user_id,)
        )
        con.commit()
        return {"success": True, "message": "Reset HWID rechazado"}
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        if con:
            con.close()

# ----------------- LOGIN -----------------
@app.post("/api/login")
def login(data: LoginRequest, request: Request):
    con = None
    try:
        con = db()
        cur = con.cursor()

        # Obtener IP del cliente
        client_ip = request.client.host if request.client else "unknown"

        # Si solo viene hwid (inicializacion), simplemente retorna OK
        if not data.username or not data.password:
            return {"success": True, "message": "Initialized"}
        
        # Rate limiting para login (5 intentos por minuto por IP)
        if not check_rate_limit(f"login_{client_ip}", max_requests=5, window=60):
            return {"success": False, "message": "Demasiados intentos de login. Intenta más tarde"}

        # Verificar si el HWID está baneado
        cur.execute("SELECT id FROM banned_ips WHERE hwid=?", (data.hwid,))
        if cur.fetchone():
            return {"success": False, "message": "Hardware baneado"}

        # Verificar si la IP está baneada
        cur.execute("SELECT id FROM banned_ips WHERE ip=?", (client_ip,))
        if cur.fetchone():
            return {"success": False, "message": "IP baneada"}

        # Si vienen credenciales, valida usuario
        if data.owner_id:
            cur.execute(
                "SELECT id, password, blocked, owner_id FROM users WHERE username=? AND owner_id=?",
                (data.username, data.owner_id)
            )
        else:
            cur.execute(
                "SELECT id, password, blocked, owner_id FROM users WHERE username=?",
                (data.username,)
            )
        u = cur.fetchone()

        if not u or not verify_password(u[1], data.password):
            return {"success": False, "message": "Invalid credentials"}

        if u[2] == 1:
            return {"success": False, "message": "Usuario bloqueado"}
        
        user_owner_id = u[3]
        if user_owner_id:
            cur.execute(
                "SELECT expires FROM licenses WHERE owner_id=? LIMIT 1",
                (user_owner_id,)
            )
            lic = cur.fetchone()
            if lic and datetime.datetime.fromisoformat(lic[0]) < datetime.datetime.utcnow():
                return {"success": False, "message": "Licencia expirada"}

        cur.execute(
            "UPDATE users SET hwid=?, ip=?, last_login=? WHERE id=?",
            (data.hwid, client_ip, datetime.datetime.utcnow().isoformat(), u[0])
        )

        return {"success": True, "message": "Logged in"}
    finally:
        if con:
            con.close()

@app.post("/api/validate")
def validate(data: ValidateRequest, request: Request):
    con = None
    try:
        con = db()
        cur = con.cursor()

        # Obtener IP del cliente
        client_ip = request.client.host if request.client else "unknown"

        if not data.username or not data.password:
            return {"success": False, "message": "Username and password required"}

        # Verificar si el HWID está baneado
        cur.execute("SELECT id FROM banned_ips WHERE hwid=?", (data.hwid,))
        if cur.fetchone():
            return {"success": False, "message": "Hardware baneado"}

        # Verificar si la IP está baneada
        cur.execute("SELECT id FROM banned_ips WHERE ip=?", (client_ip,))
        if cur.fetchone():
            return {"success": False, "message": "IP baneada"}

        if data.owner_id:
            cur.execute(
                "SELECT id, password, blocked, owner_id, is_admin, hwid, hwid_locked, hwid_reset_requested, force_logout FROM users WHERE username=? AND owner_id=?",
                (data.username, data.owner_id)
            )
        else:
            cur.execute(
                "SELECT id, password, blocked, owner_id, is_admin, hwid, hwid_locked, hwid_reset_requested, force_logout FROM users WHERE username=?",
                (data.username,)
            )
        u = cur.fetchone()

        if not u or not verify_password(u[1], data.password):
            return {"success": False, "message": "Invalid credentials"}

        if u[2] == 1:
            return {"success": False, "message": "Usuario bloqueado"}

        if u[4] == 1:
            return {"success": False, "message": "Este usuario no puede acceder con el exe"}

        if data.owner_id and u[3] != data.owner_id:
            return {"success": False, "message": "Usuario no pertenece a este perfil"}

        hwid_actual = u[5]
        hwid_locked = u[6]
        hwid_reset_requested = u[7]
        force_logout = u[8]
        
        if force_logout == 1:
            cur.execute("UPDATE users SET force_logout=0 WHERE id=?", (u[0],))
            con.commit()
            return {"success": False, "message": "FORCE_LOGOUT"}

        if hwid_actual and hwid_actual != data.hwid:
            if not hwid_locked:
                cur.execute(
                    "UPDATE users SET hwid_locked=1, hwid_reset_requested=1 WHERE id=?",
                    (u[0],)
                )
                con.commit()
            return {"success": False, "message": "HWID_CHANGED", "previous_hwid": hwid_actual, "current_hwid": data.hwid}

        if hwid_reset_requested:
            return {"success": False, "message": "HWID_RESET_PENDING"}

        cur.execute(
            "UPDATE users SET hwid=?, ip=?, last_login=? WHERE id=?",
            (data.hwid, client_ip, datetime.datetime.utcnow().isoformat(), u[0])
        )

        return {"success": True, "message": "Valid"}
    finally:
        if con:
            con.close()

@app.post("/api/request_hwid_reset")
def request_hwid_reset(data: LoginRequest):
    con = None
    try:
        con = db()
        cur = con.cursor()

        if data.owner_id:
            cur.execute(
                "SELECT id, password, hwid_reset_requested FROM users WHERE username=? AND owner_id=?",
                (data.username, data.owner_id)
            )
        else:
            cur.execute(
                "SELECT id, password, hwid_reset_requested FROM users WHERE username=?",
                (data.username,)
            )
        u = cur.fetchone()

        if not u:
            return {"success": False, "message": "Usuario no encontrado"}

        if not verify_password(u[1], data.password):
            return {"success": False, "message": "Contraseña incorrecta"}

        if not u[2]:
            return {"success": False, "message": "No hay solicitud de reset pendiente"}

        return {"success": True, "message": "Solicitud pendiente. Contacta al administrador."}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/client_info")
def client_info(data: LoginRequest, request: Request):
    con = None
    try:
        client_ip = request.client.host if request.client else "unknown"
        
        if not check_rate_limit(f"client_info_{client_ip}", max_requests=10, window=60):
            return {"success": False, "message": "Demasiados intentos"}
        
        if not data.username or not data.password:
            return {"success": False, "message": "Username and password required"}
        
        if not validate_username(data.username) or not validate_password(data.password):
            return {"success": False, "message": "Datos inválidos"}

        con = db()
        cur = con.cursor()

        cur.execute(
            "SELECT id, password, app_name, owner_id, secret, is_admin, force_logout FROM users WHERE username=?",
            (data.username,)
        )
        u = cur.fetchone()

        if not u or not verify_password(u[1], data.password):
            return {"success": False, "message": "Credenciales inválidas"}

        if u[6] == 1:
            return {"success": False, "message": "FORCE_LOGOUT"}

        app_name = u[2]
        owner_id = u[3]
        secret = u[4]

        if not owner_id or not secret or not app_name:
            if not owner_id:
                owner_id = gen_owner_id()
            if not secret:
                secret = gen_secret()
            if not app_name:
                app_name = gen_app_name()
            cur.execute(
                "UPDATE users SET app_name=?, owner_id=?, secret=? WHERE id=?",
                (app_name, owner_id, secret, u[0])
            )
            con.commit()

        return {
            "success": True,
            "app_name": app_name,
            "owner_id": owner_id,
            "secret": secret,
            "version": "1.1"
        }
    finally:
        if con:
            con.close()

@app.post("/api/version")
def api_version(data: VersionCheck):
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        server_version = "1.1"
        
        if data.owner_id:
            cur.execute("SELECT version FROM users WHERE owner_id=? LIMIT 1", (data.owner_id,))
            result = cur.fetchone()
            if result and result[0]:
                server_version = result[0]
        else:
            cur.execute("SELECT value FROM config WHERE key='app_version'")
            result = cur.fetchone()
            if result:
                server_version = result[0]
        
        client_version = data.version
        has_update = client_version != server_version
        
        return {
            "success": True,
            "version": server_version,
            "update": has_update,
            "message": "Update available" if has_update else "Latest version"
        }
    finally:
        if con:
            con.close()

@app.post("/api/admin/set_version")
def set_version(data: VersionUpdate):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("UPDATE config SET value=? WHERE key='app_version'", (data.version,))
        
        return {"success": True, "version": data.version}
    except Exception:
        raise HTTPException(500, "Error al actualizar versión")
    finally:
        if con:
            con.close()

@app.get("/api/admin/get_version")
def get_version(owner_id: str = None, secret: str = None):
    is_valid, auth_result = verify_admin(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT value FROM config WHERE key='app_version'")
        result = cur.fetchone()
        
        version = result[0] if result else "1.1"
        return {"success": True, "version": version}
    finally:
        if con:
            con.close()

@app.post("/api/client/set_version")
def client_set_version(data: VersionUpdate):
    is_valid, auth_result = verify_client(data.owner_id, data.secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute("UPDATE users SET version=? WHERE owner_id=?", (data.version, data.owner_id))
        con.commit()
        
        return {"success": True, "version": data.version, "message": "Version requirement updated"}
    finally:
        if con:
            con.close()

@app.get("/api/client/get_version/{owner_id}")
def client_get_version(owner_id: str, secret: str = None):
    is_valid, auth_result = verify_client(owner_id, secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT version FROM users WHERE owner_id=? LIMIT 1", (owner_id,))
        result = cur.fetchone()
        
        version = result[0] if result and result[0] else "1.1"
        return {"success": True, "version": version}
    finally:
        if con:
            con.close()

# ----------------- LICENSE CHECK -----------------
@app.post("/api/license")
def license_check(data: LicenseCheck):
    con = None
    try:
        con = db()
        cur = con.cursor()

        # Si no viene clave, solo inicializacion
        if not data.key:
            return {"success": True, "message": "Initialized"}

        # Verificar si el HWID está baneado
        cur.execute("SELECT id FROM banned_ips WHERE hwid=?", (data.hwid,))
        if cur.fetchone():
            return {"success": False, "message": "Hardware baneado"}

        cur.execute(
            "SELECT id, hwid, expires FROM licenses WHERE license_key=?",
            (data.key,)
        )
        lic = cur.fetchone()

        if not lic:
            return {"success": False, "message": "Invalid license"}

        if datetime.datetime.fromisoformat(lic[2]) < datetime.datetime.utcnow():
            return {"success": False, "message": "Expired"}

        if lic[1] is None:
            cur.execute(
                "UPDATE licenses SET hwid=? WHERE id=?",
                (data.hwid, lic[0])
            )
        elif lic[1] != data.hwid:
            return {"success": False, "message": "HWID mismatch"}

        return {"success": True, "message": "License OK"}
    finally:
        if con:
            con.close()

@app.post("/api/client/create_user")
def client_create_user(data: ClientCreateUser):
    is_valid, auth_result = verify_client(data.owner_id, data.secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    if not data.username or not data.password:
        return {"success": False, "message": "Username and password required"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        user_secret = gen_secret()
        cur.execute(
            "INSERT INTO users (username, password, app_name, owner_id, secret, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
            (data.username, sha256(data.password), data.username, data.owner_id, user_secret, 0)
        )
        con.commit()
        return {"success": True, "message": "User created for exe"}
    except sqlite3.IntegrityError:
        return {"success": False, "message": "User already exists"}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/client/delete_user/{user_id}")
def client_delete_user(user_id: int, data: ClientRequest):
    is_valid, auth_result = verify_client(data.owner_id, data.secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute("SELECT owner_id FROM users WHERE id=?", (user_id,))
        u = cur.fetchone()
        
        if not u or u[0] != data.owner_id:
            return {"success": False, "message": "Unauthorized"}
        
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
        con.commit()
        return {"success": True, "message": "User deleted"}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/client/update_user/{user_id}")
def client_update_user(user_id: int, data: ClientCreateUser):
    is_valid, auth_result = verify_client(data.owner_id, data.secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    if not data.password:
        return {"success": False, "message": "Password required"}
    
    if not validate_password(data.password):
        return {"success": False, "message": "Password inválida (mínimo 8 caracteres)"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute("SELECT owner_id FROM users WHERE id=?", (user_id,))
        u = cur.fetchone()
        
        if not u or u[0] != data.owner_id:
            return {"success": False, "message": "Unauthorized"}
        
        new_password = sha256(data.password)
        cur.execute("UPDATE users SET password=? WHERE id=?", (new_password, user_id))
        con.commit()
        return {"success": True, "message": "Contraseña actualizada"}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/client/block_user/{user_id}")
def client_block_user(user_id: int, data: ClientRequest):
    is_valid, auth_result = verify_client(data.owner_id, data.secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute("SELECT owner_id FROM users WHERE id=?", (user_id,))
        u = cur.fetchone()
        
        if not u or u[0] != data.owner_id:
            return {"success": False, "message": "Unauthorized"}
        
        cur.execute("UPDATE users SET force_logout=1 WHERE id=?", (user_id,))
        con.commit()
        return {"success": True, "message": "Kill sesión enviado"}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/client/ban_hwid")
def client_ban_hwid(data: BanRequest):
    is_valid, auth_result = verify_client(data.owner_id, data.secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "INSERT INTO banned_ips (ip, hwid, reason, date) VALUES (?, ?, ?, ?)",
            (None, data.hwid, data.reason, datetime.datetime.utcnow().isoformat())
        )
        con.commit()
        return {"success": True, "message": "Hardware baneado"}
    except sqlite3.IntegrityError:
        return {"success": False, "message": "Hardware ya está baneado"}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/client/ban_ip")
def client_ban_ip(data: BanRequest):
    is_valid, auth_result = verify_client(data.owner_id, data.secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "INSERT INTO banned_ips (ip, hwid, reason, date) VALUES (?, ?, ?, ?)",
            (data.ip, None, data.reason, datetime.datetime.utcnow().isoformat())
        )
        con.commit()
        return {"success": True, "message": "IP baneada"}
    except sqlite3.IntegrityError:
        return {"success": False, "message": "IP ya está baneada"}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/admin/unban_ip/{ban_id}")
def unban_ip(ban_id: int, data: AdminAuthRequest):
    is_valid, auth_result = verify_admin(data.owner_id, data.secret)
    if not is_valid:
        raise HTTPException(401, auth_result.get("message", "Acceso denegado"))
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT hwid FROM banned_ips WHERE id=?", (ban_id,))
        result = cur.fetchone()
        if result:
            hwid_to_unban = result[0]
            cur.execute("DELETE FROM banned_ips WHERE id=?", (ban_id,))
            if hwid_to_unban:
                cur.execute("UPDATE licenses SET hwid=NULL WHERE hwid=?", (hwid_to_unban,))
            con.commit()
        return {"success": True, "message": "Baneado removido"}
    except Exception:
        raise HTTPException(500, "Error al desbanear")
    finally:
        if con:
            con.close()

@app.get("/api/client/list_banned_ips/{owner_id}")
def client_list_banned_ips(owner_id: str, secret: str = None):
    is_valid, auth_result = verify_client(owner_id, secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT id, ip, hwid, reason, date FROM banned_ips ORDER BY id DESC")
        rows = cur.fetchall()
        
        banned_items = []
        for r in rows:
            banned_items.append({
                "id": r[0],
                "ip": r[1],
                "hwid": r[2],
                "reason": r[3],
                "date": r[4]
            })
        
        return {"success": True, "banned_ips": banned_items}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.get("/api/client/licenses/{owner_id}")
def client_list_licenses(owner_id: str, secret: str = None):
    is_valid, auth_result = verify_client(owner_id, secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "SELECT id, license_key, hwid, expires FROM licenses WHERE owner_id=? ORDER BY id DESC",
            (owner_id,)
        )
        rows = cur.fetchall()
        
        licenses = []
        for r in rows:
            licenses.append({
                "id": r[0],
                "key": r[1],
                "hwid": r[2],
                "expires": r[3]
            })
        
        return {"success": True, "licenses": licenses}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/client/generate_license")
def client_generate_license(data: ClientRequest):
    is_valid, auth_result = verify_client(data.owner_id, data.secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        key = gen_license()
        exp = (datetime.datetime.utcnow() + datetime.timedelta(days=30)).isoformat()
        
        cur.execute(
            "INSERT INTO licenses (license_key, expires, owner_id) VALUES (?, ?, ?)",
            (key, exp, data.owner_id)
        )
        con.commit()
        return {"success": True, "key": key, "expires": exp}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/client/delete_license/{license_id}")
def client_delete_license(license_id: int, data: ClientRequest):
    is_valid, auth_result = verify_client(data.owner_id, data.secret)
    if not is_valid:
        return {"success": False, "message": "Acceso denegado"}
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute("SELECT owner_id FROM licenses WHERE id=?", (license_id,))
        lic = cur.fetchone()
        
        if not lic or lic[0] != data.owner_id:
            return {"success": False, "message": "Unauthorized"}
        
        cur.execute("DELETE FROM licenses WHERE id=?", (license_id,))
        con.commit()
        return {"success": True, "message": "License deleted"}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.get("/api/chat/history")
def get_chat_history():
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT username, message, timestamp, avatar_url, email FROM chat_messages ORDER BY id DESC LIMIT 50")
        messages = cur.fetchall()
        return {"success": True, "messages": [{"username": m[0], "message": m[1], "timestamp": m[2], "avatar_url": m[3], "email": m[4]} for m in reversed(messages)]}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

def count_words(text: str) -> int:
    return len(text.split())

@app.get("/api/premium/subscription")
def get_subscription(owner_id: str = None, secret: str = None):
    is_valid, auth_result = verify_client(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, "Acceso denegado")
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "SELECT tier, status, expires_at, created_at FROM subscriptions WHERE owner_id=? LIMIT 1",
            (owner_id,)
        )
        sub = cur.fetchone()
        
        if sub:
            return {
                "success": True,
                "subscription": {
                    "tier": sub[0],
                    "status": sub[1],
                    "expires_at": sub[2],
                    "created_at": sub[3]
                }
            }
        return {"success": True, "subscription": {"tier": "free", "status": "inactive"}}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/premium/checkout")
def checkout(data: dict):
    owner_id = data.get("owner_id")
    secret = data.get("secret")
    
    is_valid, auth_result = verify_client(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, "Acceso denegado")
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute("SELECT email FROM users WHERE owner_id=? LIMIT 1", (owner_id,))
        user = cur.fetchone()
        
        if not user:
            return {"success": False, "message": "Usuario no encontrado"}
        
        checkout_id = secrets.token_urlsafe(16)
        
        cur.execute(
            "INSERT OR REPLACE INTO subscriptions (owner_id, tier, status, payment_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (owner_id, "gold", "pending", checkout_id, datetime.datetime.utcnow().isoformat(), datetime.datetime.utcnow().isoformat())
        )
        con.commit()
        
        checkout_url = f"https://example.com/checkout?id={checkout_id}&email={user[0]}"
        
        return {
            "success": True,
            "checkout_url": checkout_url,
            "message": "Redirigiendo al pago..."
        }
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.get("/api/premium/analytics")
def get_analytics(owner_id: str = None, secret: str = None):
    is_valid, auth_result = verify_client(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, "Acceso denegado")
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute("SELECT COUNT(*) FROM usage_logs WHERE owner_id=?", (owner_id,))
        total_executions = cur.fetchone()[0] or 0
        
        cur.execute("SELECT COUNT(DISTINCT hwid) FROM usage_logs WHERE owner_id=?", (owner_id,))
        unique_devices = cur.fetchone()[0] or 0
        
        cur.execute("SELECT country, COUNT(*) FROM usage_logs WHERE owner_id=? GROUP BY country", (owner_id,))
        countries = {row[0]: row[1] for row in cur.fetchall() if row[0]}
        
        cur.execute(
            "SELECT exe_name, hwid, country, timestamp FROM usage_logs WHERE owner_id=? ORDER BY timestamp DESC LIMIT 50",
            (owner_id,)
        )
        recent = [{"exe_name": r[0], "hwid": r[1], "country": r[2], "timestamp": r[3]} for r in cur.fetchall()]
        
        return {
            "success": True,
            "analytics": {
                "total_executions": total_executions,
                "unique_devices": unique_devices,
                "countries": countries,
                "recent_executions": recent
            }
        }
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.get("/api/premium/team")
def get_team_members(owner_id: str = None, secret: str = None):
    is_valid, auth_result = verify_client(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, "Acceso denegado")
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "SELECT id, invited_email, username, role, status, created_at FROM team_members WHERE owner_id=?",
            (owner_id,)
        )
        members = [
            {
                "id": r[0],
                "invited_email": r[1],
                "username": r[2],
                "role": r[3],
                "status": r[4],
                "created_at": r[5]
            }
            for r in cur.fetchall()
        ]
        return {"success": True, "members": members}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/premium/invite-member")
def invite_member(data: dict):
    owner_id = data.get("owner_id")
    secret = data.get("secret")
    invited_email = data.get("invited_email")
    role = data.get("role", "viewer")
    
    is_valid, auth_result = verify_client(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, "Acceso denegado")
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute(
            "INSERT INTO team_members (owner_id, invited_email, role, status, created_at) VALUES (?, ?, ?, ?, ?)",
            (owner_id, invited_email, role, "pending", datetime.datetime.utcnow().isoformat())
        )
        con.commit()
        
        return {"success": True, "message": f"Invitación enviada a {invited_email}"}
    except sqlite3.IntegrityError:
        return {"success": False, "message": "Este usuario ya ha sido invitado"}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/premium/remove-member")
def remove_member(data: dict):
    owner_id = data.get("owner_id")
    secret = data.get("secret")
    member_id = data.get("member_id")
    
    is_valid, auth_result = verify_client(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, "Acceso denegado")
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute(
            "DELETE FROM team_members WHERE id=? AND owner_id=?",
            (member_id, owner_id)
        )
        con.commit()
        
        return {"success": True, "message": "Miembro removido"}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.get("/api/premium/webhook-config")
def get_webhook_config(owner_id: str = None, secret: str = None):
    is_valid, auth_result = verify_client(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, "Acceso denegado")
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        cur.execute(
            "SELECT discord_webhook_url, enabled, log_anticracks, log_exe_launch FROM webhook_configs WHERE owner_id=? LIMIT 1",
            (owner_id,)
        )
        config = cur.fetchone()
        
        if config:
            return {
                "success": True,
                "config": {
                    "discord_webhook_url": config[0] or "",
                    "enabled": bool(config[1]),
                    "log_anticracks": bool(config[2]),
                    "log_exe_launch": bool(config[3])
                }
            }
        return {"success": True, "config": {"discord_webhook_url": "", "enabled": False, "log_anticracks": True, "log_exe_launch": True}}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/premium/webhook-config")
def set_webhook_config(data: dict):
    owner_id = data.get("owner_id")
    secret = data.get("secret")
    webhook_url = data.get("discord_webhook_url")
    log_anticracks = data.get("log_anticracks", True)
    log_exe_launch = data.get("log_exe_launch", True)
    
    is_valid, auth_result = verify_client(owner_id, secret)
    if not is_valid:
        raise HTTPException(401, "Acceso denegado")
    
    con = None
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute(
            "INSERT OR REPLACE INTO webhook_configs (owner_id, discord_webhook_url, enabled, log_anticracks, log_exe_launch, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (owner_id, webhook_url, 1 if webhook_url else 0, 1 if log_anticracks else 0, 1 if log_exe_launch else 0, datetime.datetime.utcnow().isoformat())
        )
        con.commit()
        
        return {"success": True, "message": "Webhook configurado"}
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        if con:
            con.close()

@app.post("/api/premium/test-webhook")
def test_webhook(data: dict):
    webhook_url = data.get("discord_webhook_url")
    
    if not webhook_url:
        return {"success": False, "message": "URL de webhook requerida"}
    
    try:
        test_payload = {
            "content": "✅ Test de Webhook - OxcyShop",
            "embeds": [{
                "title": "Conexión Exitosa",
                "description": "Tu webhook está funcionando correctamente",
                "color": 3066993
            }]
        }
        
        response = requests.post(webhook_url, json=test_payload)
        if response.status_code in [200, 204]:
            return {"success": True, "message": "Webhook funcionando correctamente ✅"}
        else:
            return {"success": False, "message": f"Error: {response.status_code}"}
    except Exception as e:
        return {"success": False, "message": f"Error al probar webhook: {str(e)}"}

@app.websocket("/api/ws/chat")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    con = None
    try:
        while True:
            data = await websocket.receive_text()
            msg_data = json.loads(data)
            username = msg_data.get("username", "Unknown")
            message = msg_data.get("message", "").strip()
            avatar_url = msg_data.get("avatar_url")
            email = msg_data.get("email")
            
            if not message:
                await websocket.send_json({"error": "Mensaje vacío"})
                continue
            
            if count_words(message) > 30:
                await websocket.send_json({"error": f"Máximo 30 palabras. Tu mensaje tiene {count_words(message)} palabras."})
                continue
            
            timestamp = datetime.datetime.utcnow().isoformat()
            
            try:
                con = db()
                cur = con.cursor()
                cur.execute(
                    "INSERT INTO chat_messages (username, message, timestamp, avatar_url, email) VALUES (?, ?, ?, ?, ?)",
                    (username, message, timestamp, avatar_url, email)
                )
                con.commit()
            except Exception as e:
                print(f"Error guardando mensaje: {e}")
            finally:
                if con:
                    con.close()
            
            await manager.broadcast({
                "username": username,
                "message": message,
                "timestamp": timestamp,
                "avatar_url": avatar_url,
                "email": email
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# --------- USER LOCATIONS (WORLD MAP) ---------
def get_geo_from_ip(ip: str):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=lat,lon,country,city,status", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "country": data.get("country"),
                    "city": data.get("city")
                }
    except:
        pass
    return None

@app.post("/api/location/register")
async def register_user_location(request: Request):
    try:
        body = await request.json()
        user_id = body.get("user_id")
        username = body.get("username")
        
        if not user_id or not username:
            return {"status": "error", "message": "Missing user_id or username"}
        
        client_ip = request.client.host
        if client_ip.startswith("127.") or client_ip == "localhost":
            client_ip = request.headers.get("x-forwarded-for", client_ip).split(",")[0].strip()
        
        geo_data = get_geo_from_ip(client_ip)
        
        con = db()
        cur = con.cursor()
        
        timestamp = datetime.datetime.utcnow().isoformat()
        
        cur.execute("""
            INSERT INTO user_locations (user_id, username, ip, latitude, longitude, country, city, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            username,
            client_ip,
            geo_data.get("latitude") if geo_data else None,
            geo_data.get("longitude") if geo_data else None,
            geo_data.get("country") if geo_data else "Unknown",
            geo_data.get("city") if geo_data else "Unknown",
            timestamp
        ))
        
        con.commit()
        con.close()
        
        return {"status": "success", "message": "Location registered"}
    except Exception as e:
        print(f"Error registering location: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/api/location/users")
async def get_user_locations():
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute("""
            SELECT user_id, username, latitude, longitude, country, city, timestamp 
            FROM user_locations 
            WHERE latitude IS NOT NULL AND longitude IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT 500
        """)
        
        results = cur.fetchall()
        con.close()
        
        locations = []
        for row in results:
            locations.append({
                "user_id": row[0],
                "username": row[1],
                "latitude": row[2],
                "longitude": row[3],
                "country": row[4],
                "city": row[5],
                "timestamp": row[6]
            })
        
        return {"status": "success", "locations": locations}
    except Exception as e:
        print(f"Error fetching locations: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/api/admin/user-locations")
async def get_admin_user_locations(owner_id: str, secret: str):
    try:
        con = db()
        cur = con.cursor()
        
        cur.execute("SELECT secret FROM users WHERE owner_id=? AND is_admin=1 LIMIT 1", (owner_id,))
        admin = cur.fetchone()
        
        if not admin or admin[0] != secret:
            con.close()
            return {"success": False, "message": "Unauthorized"}
        
        cur.execute("""
            SELECT ul.username, ul.latitude, ul.longitude, ul.country, ul.city, ul.timestamp
            FROM user_locations ul
            WHERE ul.user_id IN (SELECT id FROM users WHERE owner_id=?)
            AND ul.latitude IS NOT NULL AND ul.longitude IS NOT NULL
            ORDER BY ul.timestamp DESC LIMIT 500
        """, (owner_id,))
        
        results = cur.fetchall()
        con.close()
        
        users = []
        for row in results:
            users.append({
                "username": row[0],
                "latitude": row[1],
                "longitude": row[2],
                "country": row[3],
                "city": row[4],
                "timestamp": row[5]
            })
        
        return {"success": True, "users": users}
    except Exception as e:
        return {"success": False, "message": str(e)}


@app.get("/index.html")
@app.get("/")
async def serve_dashboard():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return FileResponse(os.path.join(current_dir, "index.html"))
