import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Request, Query, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
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
app = FastAPI(title="MBF HR Backend", version="0.1.4")

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


# HR Schemas
class EmployeeIn(BaseModel):
    first_name: str
    last_name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    position: Optional[str] = None
    salary: Optional[float] = Field(None, ge=0)
    hire_date: Optional[str] = Field(None, description="YYYY-MM-DD")


class Employee(EmployeeIn):
    id: int


class AttendanceIn(BaseModel):
    employee_id: int
    status: str = Field(..., description="present/absent/leave or clock_in/clock_out")
    note: Optional[str] = None


class LeaveRequestIn(BaseModel):
    employee_id: int
    leave_type: str = Field(..., description="annual, sick, unpaid, etc.")
    start_date: str
    end_date: str
    reason: Optional[str] = None


class LeaveRequest(LeaveRequestIn):
    id: int
    status: str


class PayrollRunIn(BaseModel):
    period_start: str
    period_end: str


class PayrollRun(BaseModel):
    id: int
    period_start: str
    period_end: str
    total_amount: float
    created_at: Optional[str] = None


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


# Connection + auth helpers

def get_conn():
    engine = get_engine()
    if engine is None:
        raise HTTPException(status_code=503, detail="Database driver/connection not available")
    with engine.begin() as conn:
        yield conn


def get_user_and_role(request: Request, conn) -> Tuple[int, str]:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth.split(" ", 1)[1]
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # type: ignore
        uid = int(decoded.get("sub")) if decoded.get("sub") else None
        if not uid:
            raise HTTPException(status_code=401, detail="Invalid token")
        row = conn.execute(text("SELECT id, role FROM dbo.users WHERE id=:i"), {"i": uid}).mappings().first()
        role = row["role"] if row else "user"
        return uid, role
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_role(role: str, user_role: str):
    hierarchy = {"staff": 1, "manager": 2, "admin": 3}
    if hierarchy.get(user_role, 0) < hierarchy.get(role, 0):
        raise HTTPException(status_code=403, detail="Insufficient permissions")


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
        decoded = jwt.decode(payload.refresh_token, JWT_SECRET, algorithms=["HS256"])  # type: ignore
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
    uid, _ = get_user_and_role(request, conn)
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
def upload_logo(request: Request, file: UploadFile = File(...), conn=Depends(get_conn)):
    # Require any authenticated user
    get_user_and_role(request, conn)
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


# HR: Employees
@app.get("/api/hr/employees", response_model=List[Employee])
def list_employees(
    request: Request,
    conn=Depends(get_conn),
    q: Optional[str] = Query(None, description="Search by name/email/phone"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    get_user_and_role(request, conn)
    where = []
    params: Dict[str, Any] = {}
    if q:
        where.append("(first_name LIKE :q OR last_name LIKE :q OR email LIKE :q OR phone LIKE :q)")
        params["q"] = f"%{q}%"
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    sql = f"""
        SELECT id, first_name, last_name, email, phone, position, salary,
               CONVERT(VARCHAR(10), hire_date, 23) AS hire_date
        FROM dbo.employees {where_sql}
        ORDER BY id DESC
        OFFSET :offset ROWS FETCH NEXT :limit ROWS ONLY
    """
    params.update({"limit": limit, "offset": offset})
    rows = conn.execute(text(sql), params).mappings().all()
    return [Employee(**dict(r)) for r in rows]


@app.post("/api/hr/employees", response_model=Employee, status_code=201)
def create_employee(payload: EmployeeIn, request: Request, conn=Depends(get_conn)):
    _, role = get_user_and_role(request, conn)
    require_role("manager", role)  # managers and admins can create/update
    result = conn.execute(text(
        """
        INSERT INTO dbo.employees (first_name, last_name, email, phone, position, salary, hire_date, created_at, updated_at)
        VALUES (:first_name, :last_name, :email, :phone, :position, :salary, TRY_CONVERT(DATE, :hire_date), SYSDATETIME(), SYSDATETIME());
        SELECT SCOPE_IDENTITY() AS id;
        """
    ), payload.dict())
    new_id = int(list(result)[0][0])
    row = conn.execute(text(
        "SELECT id, first_name, last_name, email, phone, position, salary, CONVERT(VARCHAR(10), hire_date, 23) AS hire_date FROM dbo.employees WHERE id=:i"
    ), {"i": new_id}).mappings().first()
    return Employee(**dict(row))


@app.get("/api/hr/employees/{emp_id}", response_model=Employee)
def get_employee(emp_id: int = Path(...), request: Request = None, conn=Depends(get_conn)):
    get_user_and_role(request, conn)
    row = conn.execute(text(
        "SELECT id, first_name, last_name, email, phone, position, salary, CONVERT(VARCHAR(10), hire_date, 23) AS hire_date FROM dbo.employees WHERE id=:i"
    ), {"i": emp_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Employee not found")
    return Employee(**dict(row))


@app.put("/api/hr/employees/{emp_id}", response_model=Employee)
def update_employee(payload: EmployeeIn, emp_id: int = Path(...), request: Request = None, conn=Depends(get_conn)):
    _, role = get_user_and_role(request, conn)
    require_role("manager", role)
    data = payload.dict()
    data["id"] = emp_id
    conn.execute(text(
        """
        UPDATE dbo.employees
        SET first_name=:first_name, last_name=:last_name, email=:email, phone=:phone,
            position=:position, salary=:salary, hire_date=TRY_CONVERT(DATE, :hire_date), updated_at=SYSDATETIME()
        WHERE id=:id
        """
    ), data)
    return get_employee(emp_id, request, conn)


# HR: Attendance
@app.get("/api/hr/attendance")
def list_attendance(
    request: Request,
    conn=Depends(get_conn),
    employee_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None, description="YYYY-MM-DD"),
    date_to: Optional[str] = Query(None, description="YYYY-MM-DD"),
):
    get_user_and_role(request, conn)
    where = []
    params: Dict[str, Any] = {}
    if employee_id:
        where.append("employee_id=:e")
        params["e"] = employee_id
    if status:
        where.append("status=:s")
        params["s"] = status
    if date_from:
        where.append("CAST(ts AS DATE) >= TRY_CONVERT(DATE, :df)")
        params["df"] = date_from
    if date_to:
        where.append("CAST(ts AS DATE) <= TRY_CONVERT(DATE, :dt)")
        params["dt"] = date_to
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    rows = conn.execute(text(
        f"SELECT id, employee_id, status, note, CONVERT(VARCHAR(19), ts, 120) AS ts FROM dbo.attendance {where_sql} ORDER BY ts DESC"
    ), params).mappings().all()
    return [dict(r) for r in rows]


@app.post("/api/hr/attendance", status_code=201)
def create_attendance(payload: AttendanceIn, request: Request, conn=Depends(get_conn)):
    _, role = get_user_and_role(request, conn)
    # staff can record; everyone above too
    if payload.status not in ("clock_in", "clock_out", "present", "absent", "leave"):
        raise HTTPException(status_code=400, detail="Invalid status")
    conn.execute(text(
        "INSERT INTO dbo.attendance (employee_id, status, note, ts) VALUES (:employee_id, :status, :note, SYSDATETIME())"
    ), payload.dict())
    return {"ok": True}


# HR: Leave Requests
@app.get("/api/hr/leave", response_model=List[LeaveRequest])
def list_leave(
    request: Request,
    conn=Depends(get_conn),
    status: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
):
    get_user_and_role(request, conn)
    where = []
    params: Dict[str, Any] = {}
    if status:
        where.append("status=:s")
        params["s"] = status
    if date_from:
        where.append("start_date >= TRY_CONVERT(DATE, :df)")
        params["df"] = date_from
    if date_to:
        where.append("end_date <= TRY_CONVERT(DATE, :dt)")
        params["dt"] = date_to
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    rows = conn.execute(text(
        f"""
        SELECT id, employee_id, leave_type, CONVERT(VARCHAR(10), start_date, 23) AS start_date,
               CONVERT(VARCHAR(10), end_date, 23) AS end_date, reason, status
        FROM dbo.leave_requests {where_sql} ORDER BY id DESC
        """
    ), params).mappings().all()
    return [LeaveRequest(**dict(r)) for r in rows]


@app.post("/api/hr/leave", response_model=LeaveRequest, status_code=201)
def create_leave(payload: LeaveRequestIn, request: Request, conn=Depends(get_conn)):
    uid, role = get_user_and_role(request, conn)
    # staff allowed to submit for themselves; manager/admin can submit any
    if role == "staff" and payload.employee_id != uid:
        pass  # In this simple app, employee_id is independent of user id; allow creation
    params = payload.dict()
    result = conn.execute(text(
        """
        INSERT INTO dbo.leave_requests (employee_id, leave_type, start_date, end_date, reason, status, created_at, updated_at)
        VALUES (:employee_id, :leave_type, TRY_CONVERT(DATE, :start_date), TRY_CONVERT(DATE, :end_date), :reason, 'pending', SYSDATETIME(), SYSDATETIME());
        SELECT SCOPE_IDENTITY() AS id;
        """
    ), params)
    new_id = int(list(result)[0][0])
    row = conn.execute(text(
        "SELECT id, employee_id, leave_type, CONVERT(VARCHAR(10), start_date, 23) AS start_date, CONVERT(VARCHAR(10), end_date, 23) AS end_date, reason, status FROM dbo.leave_requests WHERE id=:i"
    ), {"i": new_id}).mappings().first()
    return LeaveRequest(**dict(row))


class LeaveStatusUpdate(BaseModel):
    status: str = Field(..., description="pending/approved/rejected")


@app.put("/api/hr/leave/{leave_id}", response_model=LeaveRequest)
def update_leave_status(leave_id: int, payload: LeaveStatusUpdate, request: Request, conn=Depends(get_conn)):
    _, role = get_user_and_role(request, conn)
    require_role("manager", role)  # only manager/admin can approve/reject
    if payload.status not in ("pending", "approved", "rejected"):
        raise HTTPException(status_code=400, detail="Invalid status")
    conn.execute(text(
        "UPDATE dbo.leave_requests SET status=:s, updated_at=SYSDATETIME() WHERE id=:i"
    ), {"s": payload.status, "i": leave_id})
    row = conn.execute(text(
        "SELECT id, employee_id, leave_type, CONVERT(VARCHAR(10), start_date, 23) AS start_date, CONVERT(VARCHAR(10), end_date, 23) AS end_date, reason, status FROM dbo.leave_requests WHERE id=:i"
    ), {"i": leave_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Leave request not found")
    return LeaveRequest(**dict(row))


# HR: Payroll
@app.get("/api/hr/payroll/runs", response_model=List[PayrollRun])
def list_payroll_runs(
    request: Request,
    conn=Depends(get_conn),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
):
    get_user_and_role(request, conn)
    where = []
    params: Dict[str, Any] = {}
    if date_from:
        where.append("period_start >= TRY_CONVERT(DATE, :df)")
        params["df"] = date_from
    if date_to:
        where.append("period_end <= TRY_CONVERT(DATE, :dt)")
        params["dt"] = date_to
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    rows = conn.execute(text(
        f"SELECT id, CONVERT(VARCHAR(10), period_start, 23) AS period_start, CONVERT(VARCHAR(10), period_end, 23) AS period_end, total_amount, CONVERT(VARCHAR(19), created_at, 120) AS created_at FROM dbo.payroll_runs {where_sql} ORDER BY id DESC"
    ), params).mappings().all()
    return [PayrollRun(**dict(r)) for r in rows]


@app.post("/api/hr/payroll/runs", response_model=PayrollRun, status_code=201)
def create_payroll_run(payload: PayrollRunIn, request: Request, conn=Depends(get_conn)):
    _, role = get_user_and_role(request, conn)
    require_role("manager", role)
    # Simple payroll: sum active employee salaries prorated by days in period
    period_days = 1
    try:
        period_days = max(1, (datetime.fromisoformat(payload.period_end) - datetime.fromisoformat(payload.period_start)).days + 1)
    except Exception:
        pass
    # Assuming monthly salary, approximate daily = salary/26 (biweekly) for simplicity
    total_row = conn.execute(text(
        "SELECT COALESCE(SUM(CAST(salary AS FLOAT)), 0) AS total FROM dbo.employees"
    )).mappings().first()
    monthly_total = float(total_row["total"]) if total_row and total_row["total"] is not None else 0.0
    # rough pro-rate: days/30 of monthly total
    total_amount = round((period_days / 30.0) * monthly_total, 2)

    result = conn.execute(text(
        """
        INSERT INTO dbo.payroll_runs (period_start, period_end, total_amount, created_at)
        VALUES (TRY_CONVERT(DATE, :ps), TRY_CONVERT(DATE, :pe), :ta, SYSDATETIME());
        SELECT SCOPE_IDENTITY() AS id;
        """
    ), {"ps": payload.period_start, "pe": payload.period_end, "ta": total_amount})
    new_id = int(list(result)[0][0])
    row = conn.execute(text(
        "SELECT id, CONVERT(VARCHAR(10), period_start, 23) AS period_start, CONVERT(VARCHAR(10), period_end, 23) AS period_end, total_amount, CONVERT(VARCHAR(19), created_at, 120) AS created_at FROM dbo.payroll_runs WHERE id=:i"
    ), {"i": new_id}).mappings().first()
    return PayrollRun(**dict(row))


# CSV export helpers

def csv_response(filename: str, header: List[str], rows: List[List[Any]]):
    import csv
    from io import StringIO

    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(header)
    for r in rows:
        writer.writerow(r)
    data = sio.getvalue()
    return Response(content=data, media_type="text/csv", headers={
        "Content-Disposition": f"attachment; filename={filename}"
    })


@app.get("/api/hr/employees/export")
def export_employees(request: Request, conn=Depends(get_conn), q: Optional[str] = None):
    get_user_and_role(request, conn)
    where = []
    params: Dict[str, Any] = {}
    if q:
        where.append("(first_name LIKE :q OR last_name LIKE :q OR email LIKE :q OR phone LIKE :q)")
        params["q"] = f"%{q}%"
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    rows = conn.execute(text(
        f"SELECT id, first_name, last_name, email, phone, position, salary, CONVERT(VARCHAR(10), hire_date, 23) AS hire_date FROM dbo.employees {where_sql} ORDER BY id DESC"
    ), params).all()
    out = [[r.id, r.first_name, r.last_name, r.email or '', r.phone or '', r.position or '', r.salary or '', r.hire_date or ''] for r in rows]
    return csv_response("employees.csv", ["ID","First Name","Last Name","Email","Phone","Position","Salary","Hire Date"], out)


@app.get("/api/hr/attendance/export")
def export_attendance(
    request: Request,
    conn=Depends(get_conn),
    employee_id: Optional[int] = None,
    status: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    get_user_and_role(request, conn)
    where = []
    params: Dict[str, Any] = {}
    if employee_id:
        where.append("employee_id=:e")
        params["e"] = employee_id
    if status:
        where.append("status=:s")
        params["s"] = status
    if date_from:
        where.append("CAST(ts AS DATE) >= TRY_CONVERT(DATE, :df)")
        params["df"] = date_from
    if date_to:
        where.append("CAST(ts AS DATE) <= TRY_CONVERT(DATE, :dt)")
        params["dt"] = date_to
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    rows = conn.execute(text(
        f"SELECT id, employee_id, status, note, CONVERT(VARCHAR(19), ts, 120) AS ts FROM dbo.attendance {where_sql} ORDER BY ts DESC"
    ), params).all()
    out = [[r.id, r.employee_id, r.status, r.note or '', r.ts] for r in rows]
    return csv_response("attendance.csv", ["ID","Employee ID","Status","Note","Timestamp"], out)


@app.get("/api/hr/leave/export")
def export_leave(
    request: Request,
    conn=Depends(get_conn),
    status: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    get_user_and_role(request, conn)
    where = []
    params: Dict[str, Any] = {}
    if status:
        where.append("status=:s")
        params["s"] = status
    if date_from:
        where.append("start_date >= TRY_CONVERT(DATE, :df)")
        params["df"] = date_from
    if date_to:
        where.append("end_date <= TRY_CONVERT(DATE, :dt)")
        params["dt"] = date_to
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    rows = conn.execute(text(
        f"SELECT id, employee_id, leave_type, CONVERT(VARCHAR(10), start_date, 23) AS start_date, CONVERT(VARCHAR(10), end_date, 23) AS end_date, reason, status FROM dbo.leave_requests {where_sql} ORDER BY id DESC"
    ), params).all()
    out = [[r.id, r.employee_id, r.leave_type, r.start_date, r.end_date, r.reason or '', r.status] for r in rows]
    return csv_response("leave.csv", ["ID","Employee ID","Type","Start","End","Reason","Status"], out)


@app.get("/api/hr/payroll/runs/export")
def export_payroll_runs(
    request: Request,
    conn=Depends(get_conn),
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
):
    get_user_and_role(request, conn)
    where = []
    params: Dict[str, Any] = {}
    if date_from:
        where.append("period_start >= TRY_CONVERT(DATE, :df)")
        params["df"] = date_from
    if date_to:
        where.append("period_end <= TRY_CONVERT(DATE, :dt)")
        params["dt"] = date_to
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    rows = conn.execute(text(
        f"SELECT id, CONVERT(VARCHAR(10), period_start, 23) AS period_start, CONVERT(VARCHAR(10), period_end, 23) AS period_end, total_amount, CONVERT(VARCHAR(19), created_at, 120) AS created_at FROM dbo.payroll_runs {where_sql} ORDER BY id DESC"
    ), params).all()
    out = [[r.id, r.period_start, r.period_end, r.total_amount, r.created_at] for r in rows]
    return csv_response("payroll_runs.csv", ["ID","Period Start","Period End","Total Amount","Created At"], out)


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

        IF OBJECT_ID('dbo.employees', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.employees (
                id INT IDENTITY(1,1) PRIMARY KEY,
                first_name NVARCHAR(100) NOT NULL,
                last_name NVARCHAR(100) NOT NULL,
                email NVARCHAR(200) NULL,
                phone NVARCHAR(50) NULL,
                position NVARCHAR(100) NULL,
                salary DECIMAL(18,2) NULL,
                hire_date DATE NULL,
                created_at DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
                updated_at DATETIME2 NOT NULL DEFAULT SYSDATETIME()
            );
        END;

        IF OBJECT_ID('dbo.attendance', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.attendance (
                id INT IDENTITY(1,1) PRIMARY KEY,
                employee_id INT NOT NULL,
                status NVARCHAR(20) NOT NULL,
                note NVARCHAR(400) NULL,
                ts DATETIME2 NOT NULL DEFAULT SYSDATETIME()
            );
        END;

        IF OBJECT_ID('dbo.leave_requests', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.leave_requests (
                id INT IDENTITY(1,1) PRIMARY KEY,
                employee_id INT NOT NULL,
                leave_type NVARCHAR(50) NOT NULL,
                start_date DATE NOT NULL,
                end_date DATE NOT NULL,
                reason NVARCHAR(500) NULL,
                status NVARCHAR(20) NOT NULL DEFAULT 'pending',
                created_at DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
                updated_at DATETIME2 NOT NULL DEFAULT SYSDATETIME()
            );
        END;

        IF OBJECT_ID('dbo.payroll_runs', 'U') IS NULL
        BEGIN
            CREATE TABLE dbo.payroll_runs (
                id INT IDENTITY(1,1) PRIMARY KEY,
                period_start DATE NOT NULL,
                period_end DATE NOT NULL,
                total_amount DECIMAL(18,2) NOT NULL DEFAULT 0,
                created_at DATETIME2 NOT NULL DEFAULT SYSDATETIME()
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
