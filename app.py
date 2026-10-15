
import os
import re
import hmac
import time
import secrets
import hashlib
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.sessions import SessionMiddleware
from sqlalchemy import (
    create_engine, String, Integer, DateTime, ForeignKey, Text,
    select, desc
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from pwdlib import PasswordHash
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware


# ============================================================
# NEXORA CLOUD — CONFIGURATION
# ============================================================

APP_NAME = "Nexora Cloud"
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./nexora.db")
RENDER_API_KEY = os.getenv("RENDER_API_KEY", "")
RENDER_OWNER_ID = os.getenv("RENDER_OWNER_ID", "")
SECRETS_ENCRYPTION_KEY = os.getenv("SECRETS_ENCRYPTION_KEY", "")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"
ALLOWED_HOSTS = [
    x.strip() for x in os.getenv("ALLOWED_HOSTS", "*").split(",") if x.strip()
]
BOOTSTRAP_ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").lower().strip()

if len(SESSION_SECRET) < 32:
    raise RuntimeError(
        "SESSION_SECRET kamida 32 belgidan iborat kuchli tasodifiy qiymat bo‘lishi kerak."
    )

if not SECRETS_ENCRYPTION_KEY:
    raise RuntimeError(
        "SECRETS_ENCRYPTION_KEY kerak. Fernet kalitini yaratib Render Environment'ga qo‘ying."
    )

try:
    secret_box = Fernet(SECRETS_ENCRYPTION_KEY.encode())
except Exception as exc:
    raise RuntimeError("SECRETS_ENCRYPTION_KEY noto‘g‘ri Fernet kaliti.") from exc

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("nexora")
password_hash = PasswordHash.recommended()

# PostgreSQL uchun Render URL formatini moslashtirish
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine_args = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_args["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    is_admin: Mapped[bool] = mapped_column(default=False)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    repository_url: Mapped[str] = mapped_column(String(500))
    branch: Mapped[str] = mapped_column(String(120), default="main")
    runtime: Mapped[str] = mapped_column(String(40), default="python")
    render_service_id: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(40), default="Not deployed")
    live_url: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    action: Mapped[str] = mapped_column(String(100))
    details: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )


Base.metadata.create_all(engine)

app = FastAPI(title=APP_NAME, docs_url=None, redoc_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="nexora_session",
    max_age=60 * 60 * 8,
    same_site="lax",
    https_only=COOKIE_SECURE,
)

if ALLOWED_HOSTS != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

if os.getenv("FORCE_HTTPS", "false").lower() == "true":
    app.add_middleware(HTTPSRedirectMiddleware)


# ============================================================
# BASIC SECURITY
# ============================================================

# Simple per-process rate limiter. For multiple instances, use Redis.
_rate_data = {}


def rate_limit(key: str, limit: int = 8, window: int = 60):
    now = time.monotonic()
    bucket = _rate_data.get(key, [])
    bucket = [t for t in bucket if now - t < window]
    if len(bucket) >= limit:
        raise HTTPException(429, "Juda ko‘p urinish. Biroz kuting.")
    bucket.append(now)
    _rate_data[key] = bucket


def client_key(request: Request) -> str:
    # X-Forwarded-For headeriga ishonmaymiz: uni mijoz soxtalashtirishi mumkin.
    return request.client.host if request.client else "unknown"


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def verify_csrf(request: Request, supplied: str):
    expected = request.session.get("csrf", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise HTTPException(403, "CSRF tekshiruvi muvaffaqiyatsiz.")


def current_user(request: Request, db):
    uid = request.session.get("uid")
    if not isinstance(uid, int):
        return None
    user = db.get(User, uid)
    if not user or not user.is_active:
        request.session.clear()
        return None
    return user


def require_user(request: Request, db):
    user = current_user(request, db)
    if not user:
        raise HTTPException(401, "Avval tizimga kiring.")
    return user


def audit(db, user_id: int, action: str, details: str = ""):
    # Maxfiy kalitlar yoki parollar auditga yozilmaydi.
    db.add(AuditLog(
        user_id=user_id,
        action=action[:100],
        details=details[:500],
    ))
    db.commit()


def safe_github_url(url: str) -> bool:
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme != "https" or parsed.hostname != "github.com":
            return False
        if parsed.username or parsed.password or parsed.port:
            return False
        if parsed.query or parsed.fragment:
            return False
        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(parts) != 2:
            return False
        if not all(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", p) for p in parts):
            return False
        return not parts[1].endswith(".git") or len(parts[1]) > 4
    except Exception:
        return False


def render_headers():
    if not RENDER_API_KEY:
        raise HTTPException(503, "Render API sozlanmagan.")
    return {
        "Authorization": f"Bearer {RENDER_API_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


# ============================================================
# HTML HELPERS — escape dynamic values before displaying them
# ============================================================

from html import escape


def page(title: str, body: str, user=None, csrf="") -> HTMLResponse:
    email = escape(user.email) if user else ""
    nav = (
        f'<span class="muted">{email}</span>'
        '<form method="post" action="/logout" class="inline">'
        f'<input type="hidden" name="csrf" value="{escape(csrf)}">'
        '<button class="btn secondary">Chiqish</button></form>'
        if user else '<a class="btn" href="/login">Kirish</a>'
    )
    html = f"""<!doctype html>
<html lang="uz">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>{escape(title)} · {APP_NAME}</title>
<style>
:root{{--bg:#080d1b;--panel:#111a2d;--line:#263653;--text:#edf4ff;
--muted:#9aabc5;--blue:#5a8cff;--cyan:#42d9ee}}
*{{box-sizing:border-box}}
body{{margin:0;background:radial-gradient(ellipse at top,#14234a 0,#080d1b 55%);
color:var(--text);font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}}
a{{color:#91caff;text-decoration:none}}
header{{border-bottom:1px solid var(--line);background:#080d1beF}}
.bar{{max-width:1120px;margin:auto;padding:16px 22px;display:flex;
align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}}
.brand{{font-weight:900;font-size:21px;letter-spacing:-.5px}}
.brand span{{color:var(--cyan)}}
main{{max-width:1120px;margin:32px auto;padding:0 20px 70px}}
h1{{font-size:clamp(27px,4vw,42px);line-height:1.15;margin:8px 0 12px}}
h2{{font-size:20px;margin-top:0}}
p{{color:var(--muted)}}
.panel{{background:linear-gradient(145deg,#121d32,#0d1527);border:1px solid var(--line);
border-radius:18px;padding:22px;margin:16px 0;box-shadow:0 12px 40px #0002}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}}
label{{display:block;margin:12px 0 6px;color:#c8d8f0;font-weight:650}}
input,select{{width:100%;padding:12px 13px;border-radius:10px;border:1px solid #344766;
background:#080f20;color:var(--text);font:inherit}}
input:focus,select:focus,button:focus,a:focus{{outline:2px solid var(--cyan);outline-offset:2px}}
.btn,button{{display:inline-block;border:0;border-radius:10px;padding:11px 15px;
background:linear-gradient(110deg,#477bff,#6e63f5);color:white;font-weight:750;
cursor:pointer;font:inherit;text-decoration:none}}
.secondary{{background:#1b2941;border:1px solid #354865}}
.inline{{display:inline}}
.muted{{color:var(--muted);font-size:13px}}
table{{width:100%;border-collapse:collapse;overflow-wrap:anywhere}}
th,td{{padding:12px 9px;border-bottom:1px solid var(--line);text-align:left}}
th{{color:#b9c9e2;font-size:13px}}
.badge{{display:inline-block;padding:3px 9px;border:1px solid #395071;
border-radius:99px;font-size:12px;color:#c6ddff}}
.error{{color:#ff9eaa}}
.footer{{color:#6f829f;font-size:12px;margin-top:28px}}
@media(max-width:600px){{main{{margin-top:20px;padding:0 13px 45px}}.panel{{padding:16px}}}}
</style>
</head>
<body>
<header><div class="bar"><a class="brand" href="/">NEXORA <span>CLOUD</span></a>
<nav>{nav}</nav></div></header>
<main>{body}<div class="footer">Nexora Cloud · Code. Deploy. Scale.</div></main>
</body></html>"""
    response = HTMLResponse(html)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; object-src 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


def error_page(message: str, status: int = 400):
    return HTMLResponse(
        f'<section class="panel"><h1>Xatolik</h1><p class="error">'
        f'{escape(message)}</p><a href="/">Bosh sahifa</a></section>',
        status_code=status,
    )


# ============================================================
# PUBLIC PAGES
# ============================================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    with SessionLocal() as db:
        user = current_user(request, db)
        token = csrf_token(request)
        if user:
            return RedirectResponse("/dashboard", status_code=303)
        body = """
<section class="panel">
<span class="badge">DEVELOPER CLOUD PLATFORM</span>
<h1>Kodingizni yozing. <br><span style="color:#42d9ee">Loyihangizni ishga tushiring.</span></h1>
<p>Nexora Cloud — loyihalarni boshqarish va konfiguratsiya qilingan hosting xizmatiga
deploy yuborish uchun platforma.</p>
<div class="grid">
<div class="panel"><h2>🔐 Himoyalangan hisob</h2><p>Parollar xeshlangan, sessiyalar himoyalangan.</p></div>
<div class="panel"><h2>🚀 Deploy boshqaruvi</h2><p>Sozlangan Render xizmatlariga deploy so‘rovi yuborish.</p></div>
<div class="panel"><h2>🧩 Loyiha boshqaruvi</h2><p>Har bir hisob faqat o‘z loyihalarini boshqaradi.</p></div>
</div>
<a class="btn" href="/register">Bepul hisob yaratish</a>
<a class="btn secondary" href="/login">Kirish</a>
</section>
"""
        return page("Bosh sahifa", body, user, token)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    with SessionLocal() as db:
        user = current_user(request, db)
        if user:
            return RedirectResponse("/dashboard", status_code=303)
        token = csrf_token(request)
        body = f"""
<section class="panel" style="max-width:540px;margin:auto">
<h1>Hisob yaratish</h1><p>Parolingizni boshqa saytlarda qayta ishlatmang.</p>
<form method="post" action="/register">
<input type="hidden" name="csrf" value="{escape(token)}">
<label>Email</label><input name="email" type="email" maxlength="254" required autocomplete="email">
<label>Parol (kamida 12 belgi)</label>
<input name="password" type="password" minlength="12" maxlength="256" required autocomplete="new-password">
<button style="margin-top:18px">Hisob yaratish</button>
</form><p>Hisobingiz bormi? <a href="/login">Kiring</a></p></section>
"""
        return page("Ro‘yxatdan o‘tish", body, user, token)


@app.post("/register")
def register(request: Request, email: str = Form(...),
             password: str = Form(...), csrf: str = Form(...)):
    rate_limit("register:" + client_key(request), 5, 300)
    verify_csrf(request, csrf)
    email = email.strip().lower()
    if len(email) > 254 or not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", email
    ):
        return error_page("Email manzili noto‘g‘ri.")
    if len(password) < 12 or len(password) > 256:
        return error_page("Parol 12–256 belgi oralig‘ida bo‘lishi kerak.")
    if len(set(password)) < 5:
        return error_page("Kuchliroq, taxmin qilish qiyin bo‘lgan parol tanlang.")
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.email == email)):
            return error_page("Bu email bilan hisob mavjud.")
        admin = bool(BOOTSTRAP_ADMIN_EMAIL and email == BOOTSTRAP_ADMIN_EMAIL)
        user = User(email=email, password_hash=password_hash.hash(password), is_admin=admin)
        db.add(user)
        db.commit()
        db.refresh(user)
        request.session.clear()
        request.session["uid"] = user.id
        csrf_token(request)
        audit(db, user.id, "account.registered")
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    with SessionLocal() as db:
        user = current_user(request, db)
        if user:
            return RedirectResponse("/dashboard", status_code=303)
        token = csrf_token(request)
        body = f"""
<section class="panel" style="max-width:540px;margin:auto">
<h1>Hisobga kirish</h1>
<form method="post" action="/login">
<input type="hidden" name="csrf" value="{escape(token)}">
<label>Email</label><input name="email" type="email" maxlength="254" required autocomplete="username">
<label>Parol</label><input name="password" type="password" maxlength="256" required autocomplete="current-password">
<button style="margin-top:18px">Kirish</button></form>
<p>Yangi foydalanuvchimisiz? <a href="/register">Hisob yarating</a></p>
</section>"""
        return page("Kirish", body, user, token)


@app.post("/login")
def login(request: Request, email: str = Form(...),
          password: str = Form(...), csrf: str = Form(...)):
    rate_limit("login:" + client_key(request), 8, 300)
    verify_csrf(request, csrf)
    email = email.strip().lower()[:254]
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        # Dummy hash verification is not used here; keep the response generic.
        if not user or not user.is_active or not password_hash.verify(
            password, user.password_hash
        ):
            logger.warning("Failed login attempt")
            return error_page("Email yoki parol noto‘g‘ri.", 401)
        request.session.clear()
        request.session["uid"] = user.id
        csrf_token(request)
        audit(db, user.id, "account.login")
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf: str = Form(...)):
    verify_csrf(request, csrf)
    uid = request.session.get("uid")
    request.session.clear()
    if isinstance(uid, int):
        with SessionLocal() as db:
            audit(db, uid, "account.logout")
    return RedirectResponse("/", status_code=303)


# ============================================================
# DASHBOARD AND PROJECTS
# ============================================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    with SessionLocal() as db:
        user = current_user(request, db)
        if not user:
            return RedirectResponse("/login", status_code=303)
        token = csrf_token(request)
        projects = db.scalars(
            select(Project).where(Project.owner_id == user.id)
            .order_by(desc(Project.created_at))
        ).all()

        rows = ""
        for p in projects:
            rows += (
                "<tr><td><strong>" + escape(p.name) + "</strong></td>"
                "<td>" + escape(p.runtime) + "</td>"
                "<td><span class='badge'>" + escape(p.status) + "</span></td>"
                "<td>" + (
                    f'<a href="{escape(p.live_url, quote=True)}" rel="noopener noreferrer">Ochish</a>'
                    if p.live_url.startswith("https://") else "—"
                ) + "</td><td><a href='/projects/" + str(p.id) + "'>Boshqarish</a></td></tr>"
            )
        if not rows:
            rows = '<tr><td colspan="5">Hali loyiha yo‘q. Birinchi loyihangizni yarating.</td></tr>'

        body = f"""
<h1>Dashboard</h1><p>Salom, {escape(user.email)}. Loyihalaringiz shu yerda.</p>
<div class="grid">
<div class="panel"><p>LOYIHALAR</p><h2>{len(projects)}</h2></div>
<div class="panel"><p>AKKAUNT</p><h2>{'Administrator' if user.is_admin else 'Foydalanuvchi'}</h2></div>
<div class="panel"><p>DEPLOY PROVIDER</p><h2>{'Render ulangan' if RENDER_API_KEY else 'Sozlanmagan'}</h2></div>
</div>
<section class="panel"><h2>Yangi loyiha</h2>
<form method="post" action="/projects">
<input type="hidden" name="csrf" value="{escape(token)}">
<label>Loyiha nomi</label><input name="name" maxlength="80" required placeholder="my-telegram-bot">
<label>GitHub repository URL (HTTPS)</label>
<input name="repository_url" maxlength="500" required placeholder="https://github.com/user/repository">
<label>Branch</label><input name="branch" maxlength="120" value="main" required>
<label>Runtime</label><select name="runtime">
<option value="python">Python / Telegram bot</option>
<option value="fastapi">FastAPI</option>
<option value="flask">Flask</option>
<option value="node">Node.js</option>
<option value="static">Static website</option>
<option value="worker">Background worker</option>
</select>
<button style="margin-top:18px">Loyiha yaratish</button>
</form></section>
<section class="panel"><h2>Loyihalarim</h2><div style="overflow-x:auto"><table>
<thead><tr><th>Nomi</th><th>Runtime</th><th>Status</th><th>URL</th><th></th></tr></thead>
<tbody>{rows}</tbody></table></div></section>
"""
        return page("Dashboard", body, user, token)


@app.post("/projects")
def create_project(request: Request, name: str = Form(...),
                   repository_url: str = Form(...), branch: str = Form("main"),
                   runtime: str = Form("python"), csrf: str = Form(...)):
    verify_csrf(request, csrf)
    with SessionLocal() as db:
        user = require_user(request, db)
        name = name.strip()
        branch = branch.strip()
        allowed_runtimes = {"python", "fastapi", "flask", "node", "static", "worker"}
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}", name):
            return error_page("Loyiha nomi formati noto‘g‘ri.")
        if not re.fullmatch(r"[A-Za-z0-9._/-]{1,120}", branch):
            return error_page("Branch nomi noto‘g‘ri.")
        if runtime not in allowed_runtimes:
            return error_page("Runtime turi qo‘llab-quvvatlanmaydi.")
        if not safe_github_url(repository_url):
            return error_page("Faqat haqiqiy HTTPS GitHub repository URL manzili mumkin.")
        project = Project(
            owner_id=user.id,
            name=name,
            repository_url=repository_url.strip().rstrip("/"),
            branch=branch,
            runtime=runtime,
        )
        db.add(project)
        db.commit()
        db.refresh(project)
        audit(db, user.id, "project.created", f"project_id={project.id}")
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/projects/{project_id}", response_class=HTMLResponse)
def project_detail(request: Request, project_id: int):
    with SessionLocal() as db:
        user = current_user(request, db)
        if not user:
            return RedirectResponse("/login", status_code=303)

        # Ownership is checked on the server for every private project.
        project = db.scalar(select(Project).where(
            Project.id == project_id, Project.owner_id == user.id
        ))
        if not project:
            raise HTTPException(404, "Loyiha topilmadi.")

        token = csrf_token(request)
        service_status = "Render service ID kiritilmagan"
        body = f"""
<a href="/dashboard">← Dashboard</a>
<section class="panel">
<h1>{escape(project.name)}</h1>
<p><span class="badge">{escape(project.runtime)}</span>
<span class="badge">{escape(project.status)}</span></p>
<p>Repository: <a href="{escape(project.repository_url, quote=True)}"
rel="noopener noreferrer">{escape(project.repository_url)}</a></p>
<p>Branch: <strong>{escape(project.branch)}</strong></p>
<p>Project ID: {project.id}</p>
<p>Render service: {escape(project.render_service_id or 'Ulanmagan')}</p>
<p>Live URL: {escape(project.live_url or 'Hozircha yo‘q')}</p>
</section>
<section class="panel"><h2>Deploy</h2>
<p>Deploy ishlashi uchun Render API kaliti va ushbu loyihaga mos haqiqiy Render Service ID kerak.
Repository Render xizmatida ham sozlangan bo‘lishi lozim.</p>
<form method="post" action="/projects/{project.id}/connect-render">
<input type="hidden" name="csrf" value="{escape(token)}">
<label>Render Service ID</label>
<input name="service_id" maxlength="120" required
value="{escape(project.render_service_id)}" placeholder="srv-...">
<button style="margin-top:12px">Service ulash</button></form>
<form method="post" action="/projects/{project.id}/deploy" style="margin-top:18px">
<input type="hidden" name="csrf" value="{escape(token)}">
<button>Deploy boshlash</button></form>
</section>
"""
        return page(project.name, body, user, token)


@app.post("/projects/{project_id}/connect-render")
def connect_render(request: Request, project_id: int,
                   service_id: str = Form(...), csrf: str = Form(...)):
    verify_csrf(request, csrf)
    service_id = service_id.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,120}", service_id):
        return error_page("Render Service ID formati noto‘g‘ri.")
    with SessionLocal() as db:
        user = require_user(request, db)
        project = db.scalar(select(Project).where(
            Project.id == project_id, Project.owner_id == user.id
        ))
        if not project:
            raise HTTPException(404, "Loyiha topilmadi.")
        if not RENDER_API_KEY:
            return error_page("Render API kaliti sozlanmagan.", 503)
        project.render_service_id = service_id
        db.commit()
        audit(db, user.id, "project.render_service_connected", f"project_id={project.id}")
    return RedirectResponse(f"/projects/{project_id}", status_code=303)


@app.post("/projects/{project_id}/deploy")
async def deploy_project(request: Request, project_id: int,
                         csrf: str = Form(...)):
    verify_csrf(request, csrf)
    with SessionLocal() as db:
        user = require_user(request, db)
        project = db.scalar(select(Project).where(
            Project.id == project_id, Project.owner_id == user.id
        ))
        if not project:
            raise HTTPException(404, "Loyiha topilmadi.")
        if not project.render_service_id:
            return error_page("Avval loyihaga Render Service ID ulang.")
        if not RENDER_API_KEY:
            return error_page("Render API kaliti sozlanmagan.", 503)

        # Verify that the service exists and is accessible to this API key.
        headers = render_headers()
        service_url = (
            "https://api.render.com/v1/services/" + project.render_service_id
        )
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                check = await client.get(service_url, headers=headers)
                if check.status_code == 404:
                    return error_page("Render service topilmadi yoki unga ruxsat yo‘q.", 404)
                check.raise_for_status()
                result = await client.post(
                    service_url + "/deploys",
                    headers=headers,
                    json={"clearCache": "do_not_clear"},
                )
                result.raise_for_status()
                deploy_data = result.json()
        except httpx.HTTPStatusError as exc:
            logger.warning("Render API rejected deploy request: status=%s", exc.response.status_code)
            return error_page(
                f"Render deploy so‘rovini rad etdi (HTTP {exc.response.status_code}).", 502
            )
        except (httpx.TimeoutException, httpx.RequestError):
            logger.exception("Render API request failed")
            return error_page("Render API bilan bog‘lanib bo‘lmadi. Keyinroq qayta urinib ko‘ring.", 502)

        project.status = "Deploy queued"
        db.commit()
        audit(db, user.id, "project.deploy_requested", f"project_id={project.id}")

        # This confirms the API accepted the request, not that deployment is live.
        deploy_id = deploy_data.get("id") or deploy_data.get("deploy", {}).get("id", "")
        body = (
            "<section class='panel'><h1>Deploy so‘rovi yuborildi</h1>"
            "<p>Render so‘rovni qabul qildi. Bu hali deploy muvaffaqiyatli tugadi degani emas.</p>"
            f"<p>Deploy ID: {escape(str(deploy_id)[:150]) or 'Render javob berdi'}</p>"
            f"<a class='btn' href='/projects/{project.id}'>Loyihaga qaytish</a>"
            "</section>"
        )
        return page("Deploy", body, user, csrf_token(request))


# ============================================================
# ACCOUNT, STATUS AND SECURITY HEADERS
# ============================================================

@app.get("/api/me")
def api_me(request: Request):
    with SessionLocal() as db:
        user = current_user(request, db)
        if not user:
            raise HTTPException(401, "Kirish talab qilinadi.")
        return {
            "id": user.id,
            "email": user.email,
            "is_admin": user.is_admin,
        }


@app.get("/health")
def health():
    # Do not expose secrets, internal paths, or environment values.
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        return {"status": "ok", "database": "connected"}
    except Exception:
        logger.exception("Health check database failure")
        return JSONResponse(
            {"status": "degraded", "database": "unavailable"},
            status_code=503,
        )


@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/") or request.url.path == "/health":
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    return error_page(str(exc.detail), exc.status_code)


@app.middleware("http")
async def common_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Cache-Control", "no-store")
    return response
