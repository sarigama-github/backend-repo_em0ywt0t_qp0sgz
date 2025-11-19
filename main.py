import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
import jwt
from passlib.context import CryptContext
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

# Ensure uploads directory exists before mounting static files (Starlette requires it)
os.makedirs("uploads", exist_ok=True)

# App setup
app = FastAPI(title="MBF HR Backend", version="0.1.2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security and auth
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
REFRESH_EXPIRE_DAYS = int(os.getenv("REFRESH_EXPIRE_DAYS", "7"))
BOOTSTRAP_KEY = os.getenv("BOOTSTRAP_KEY", "dev-bootstrap")

# Database (SQL Server) - do NOT hard-fail on startup
SQL_SERVER_CONN = os.getenv(
    "SQL_SERVER_CONN",
    # Placeholder; in this environment a real SQL Server may be unavailable
    "Driver={ODBC Driver 18 for SQL Server};Server=localhost;Database=master;UID=sa;PWD=Your_password123;Encrypt=no;TrustServerCertificate=yes;",
)

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        try:
            connection_url = URL.create("mssql+pyodbc", query={"odbc_connect": SQL_SERVER_CONN})
            _engine = create_engine(connection_url, pool_pre_ping=True, pool_recycle=1800)
        except Exception:
            # Engine creation failed (likely driver missing). Keep as None; endpoints will handle.
            _engine = None
    return _engine


# Models
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


class Profile(BaseModel):
    id: Optional[int] = None
    username: str = ""
    display_name: Optional[str] = None
    role: str = "user"
    currency: str = "TOP"  # Tongan Paʻanga
    logo_url: Optional[str] = None


# Error handler with request id
@app.middleware("http")
async def add_request_context(request: Request, call_next):
    request_id = os.urandom(8).hex()
    try:
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        return response
    except HTTPException as he:
        return JSONResponse(
            status_code=he.status_code,
            content={"error": he.detail, "request_id": request_id},
        )
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"error": "Internal Server Error", "request_id": request_id},
        )


# Token helpers

def create_tokens(sub: str):
    now = datetime.now(timezone.utc)
    access_payload = {"sub": sub, "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES)}
    refresh_payload = {"sub": sub, "exp": now + timedelta(days=REFRESH_EXPIRE_DAYS), "type": "refresh"}
    return (
        jwt.encode(access_payload, JWT_SECRET, algorithm="HS256"),
        jwt.encode(refresh_payload, JWT_SECRET, algorithm="HS256"),
    )


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


# Connection dependency

def get_conn():
    engine = get_engine()
    if engine is None:
        raise HTTPException(status_code=503, detail="Database driver/connection not available")
    with engine.begin() as conn:
        yield conn


# Auth endpoints (password-only for now)
@app.post("/api/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, conn=Depends(get_conn)):
    row = conn.execute(
        text("SELECT id, username, password_hash, role, display_name FROM dbo.users WHERE username=:u"),
        {"u": payload.username},
    ).fetchone()
    if not row or not verify_password(payload.password, row.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access, refresh = create_tokens(str(row.id))
    return TokenResponse(access_token=access, refresh_token=refresh)


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/api/auth/refresh", response_model=TokenResponse)
def refresh_token(payload: RefreshRequest):
    try:
        decoded = jwt.decode(payload.refresh_token, JWT_SECRET, algorithms=["HS256"])
        if decoded.get("type") != "refresh":
            raise HTTPException(status_code=400, detail="Invalid token type")
        sub = decoded["sub"]
        access, refresh = create_tokens(sub)
        return TokenResponse(access_token=access, refresh_token=refresh)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Profile and settings
@app.get("/api/profile", response_model=Profile)
def get_profile(request: Request, conn=Depends(get_conn)):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth.split(" ", 1)[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    uid = int(decoded.get("sub")) if decoded.get("sub") else None
    user = conn.execute(
        text("SELECT id, username, role, display_name FROM dbo.users WHERE id=:i"),
        {"i": uid},
    ).fetchone()
    org = conn.execute(text("SELECT TOP 1 currency, logo_url FROM dbo.org_settings ORDER BY id DESC")).fetchone()
    return Profile(
        id=user.id if user else None,
        username=user.username if user else "",
        display_name=user.display_name if user else None,
        role=(user.role if user else "user"),
        currency=(org.currency if org and org.currency else "TOP"),
        logo_url=(org.logo_url if org else None),
    )


# Logo upload (stores URL in settings)
@app.post("/api/settings/logo")
def upload_logo(file: UploadFile = File(...), conn=Depends(get_conn)):
    uploads_dir = os.path.join(os.getcwd(), "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    fname = f"logo_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
    fpath = os.path.join(uploads_dir, fname)
    with open(fpath, "wb") as f:
        f.write(file.file.read())
    public_url = f"/uploads/{fname}"
    conn.execute(
        text(
            "UPDATE dbo.org_settings SET logo_url=:u, updated_at=SYSDATETIME() WHERE id=(SELECT TOP 1 id FROM dbo.org_settings ORDER BY id DESC)"
        ),
        {"u": public_url},
    )
    return {"logo_url": public_url}


# Admin bootstrap endpoint (idempotent): creates base tables and seeds admin + org settings
@app.post("/api/admin/bootstrap")
def bootstrap(
    key: str = Query(..., description="Protection key; must match BOOTSTRAP_KEY env var"),
    conn=Depends(get_conn),
):
    if key != BOOTSTRAP_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Create tables if they don't exist
    conn.execute(text(
        """
        IF OBJECT_ID('dbo.users', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.users (
                id INT IDENTITY(1,1) PRIMARY KEY,
                username NVARCHAR(100) NOT NULL UNIQUE,
                password_hash NVARCHAR(255) NOT NULL,
                role NVARCHAR(50) NOT NULL DEFAULT 'admin',
                display_name NVARCHAR(150) NULL,
                created_at DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
                updated_at DATETIME2 NOT NULL DEFAULT SYSDATETIME()
            );
        END;

        IF OBJECT_ID('dbo.org_settings', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.org_settings (
                id INT IDENTITY(1,1) PRIMARY KEY,
                currency NVARCHAR(10) NOT NULL DEFAULT 'TOP',
                logo_url NVARCHAR(400) NULL,
                created_at DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
                updated_at DATETIME2 NOT NULL DEFAULT SYSDATETIME()
            );
        END;
        """
    ))

    # Seed org settings if empty
    conn.execute(text(
        """
        IF NOT EXISTS (SELECT 1 FROM dbo.org_settings)
        BEGIN
            INSERT INTO dbo.org_settings (currency) VALUES ('TOP');
        END;
        """
    ))

    # Seed admin user if not exists
    admin_user = "admin"
    admin_pass_env = os.getenv("ADMIN_DEFAULT_PASSWORD", "ChangeMe123!")
    admin_hash = hash_password(admin_pass_env)
    conn.execute(text(
        """
        IF NOT EXISTS (SELECT 1 FROM dbo.users WHERE username = :u)
        BEGIN
            INSERT INTO dbo.users (username, password_hash, role, display_name)
            VALUES (:u, :h, 'admin', 'Administrator');
        END;
        """
    ), {"u": admin_user, "h": admin_hash})

    return {
        "status": "ok",
        "message": "Bootstrap completed (idempotent)",
        "admin_username": admin_user,
        "admin_password_hint": "Use ADMIN_DEFAULT_PASSWORD env var to control initial password",
    }


# Static files for uploads
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")


@app.get("/")
def read_root():
    return {"message": "MBF HR Backend running"}


@app.get("/health")
def health():
    # Try a lightweight DB ping, but don't fail the endpoint
    try:
        engine = get_engine()
        if engine is None:
            return {"status": "degraded", "db": "unavailable"}
        with engine.begin() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "db": "ok"}
    except Exception as e:
        return {"status": "degraded", "db": f"error: {str(e)[:80]}"}


@app.get("/test")
def test_database():
    try:
        engine = get_engine()
        if engine is None:
            return {"backend": "running", "db": "unavailable (driver/connection)", "ping": None}
        with engine.begin() as conn:
            v = conn.execute(text("SELECT 1 AS ok")).scalar()
        return {"backend": "running", "db": "ok", "ping": v}
    except Exception as e:
        return {"backend": "running", "db": f"error: {str(e)[:100]}"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
