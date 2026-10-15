import os
import re
import secrets
from datetime import datetime
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.sessions import SessionMiddleware
from pwdlib import PasswordHash
from sqlalchemy import (
    create_engine, String, Integer, DateTime, ForeignKey, Text
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, sessionmaker, relationship
)

APP_NAME = "Nexora Cloud"
SESSION_SECRET = os.getenv("SESSION_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./nexora.db")
RENDER_API_KEY = os.getenv("RENDER_API_KEY", "")

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET ni Environment sozlamasiga kiriting.")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine_args = {}
if DATABASE_URL.startswith("sqlite"):
    engine_args["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, pool_pre_ping=True, **engine_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    projects: Mapped[list["Project"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    kind: Mapped[str] = mapped_column(String(20))
    repo_url: Mapped[str] = mapped_column(Text)
    render_service_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)

    owner: Mapped[User] = relationship(back_populates="projects")


Base.metadata.create_all(engine)

app = FastAPI(title=APP_NAME)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=True,
    max_age=60 * 60 * 24 * 7,
)
password_hasher = PasswordHash.recommended()


def page(title: str, body: str, user=None) -> HTMLResponse:
    nav = ""
    if user:
        nav = f"""
        <nav>
          <a href="/dashboard">Dashboard</a>
          <a href="/projects">Loyihalar</a>
          <form action="/logout" method="post">
            <button class="secondary">Chiqish</button>
          </form>
        </nav>
        """
    html = f"""<!doctype html>
<html lang="uz">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · {APP_NAME}</title>
<style>
:root{{--bg:#080d19;--panel:#111a2c;--line:#263550;--cyan:#54e5ff;
--text:#f1f6ff;--muted:#9aacc8;}}
*{{box-sizing:border-box}}
body{{margin:0;background:radial-gradient(ellipse at top,#17264a,var(--bg) 60%);
color:var(--text);font:15px system-ui,sans-serif;min-height:100vh}}
header{{padding:20px 5%;border-bottom:1px solid var(--line);
display:flex;justify-content:space-between;align-items:center;gap:15px}}
.brand{{font-size:22px;font-weight:800;color:var(--cyan)}}
nav{{display:flex;gap:16px;align-items:center;flex-wrap:wrap}}
a{{color:var(--cyan);text-decoration:none}}
main{{width:min(1000px,92%);margin:38px auto}}
h1{{font-size:clamp(27px,5vw,42px);margin:0 0 12px}}
p,.muted{{color:var(--muted);line-height:1.6}}
.panel{{background:var(--panel);border:1px solid var(--line);
padding:22px;border-radius:18px;margin:18px 0;overflow-wrap:anywhere}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}}
input,select{{width:100%;padding:13px;margin:7px 0 15px;background:#0a1221;
border:1px solid var(--line);border-radius:9px;color:var(--text)}}
button,.button{{display:inline-block;border:0;border-radius:9px;padding:12px 16px;
background:var(--cyan);color:#06111e;font-weight:750;cursor:pointer}}
.secondary{{background:#263550;color:white}}
label{{color:var(--muted)}}
small{{color:var(--muted)}}
</style>
</head>
<body>
<header><div class="brand">◈ NEXORA CLOUD</div>{nav}</header>
<main>{body}</main>
</body></html>"""
    return HTMLResponse(html)


def current_user(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return None
    with SessionLocal() as db:
        return db.get(User, uid)


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(401, "Avval tizimga kiring.")
    return user


def safe_repo_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise HTTPException(400, "GitHub repozitoriy URL manzilini kiriting.")
    if not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?", parsed.path):
        raise HTTPException(400, "GitHub URL formati noto‘g‘ri.")
    return value.strip().rstrip("/")


def render_headers():
    if not RENDER_API_KEY:
        raise HTTPException(
            503,
            "Render API kaliti sozlanmagan. Environment bo‘limiga "
            "RENDER_API_KEY kiriting."
        )
    return {
        "Authorization": f"Bearer {RENDER_API_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


async def render_request(method: str, path: str, payload=None):
    url = "https://api.render.com/v1" + path
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.request(
            method, url, headers=render_headers(), json=payload
        )
    if response.is_error:
        # API kaliti yoki maxfiy javob ma'lumotlarini sahifaga chiqarmaymiz.
        raise HTTPException(
            response.status_code,
            "Render API so‘rovni rad etdi. API sozlamalari va loyiha "
            "ruxsatlarini tekshiring."
        )
    if not response.content:
        return {}
    return response.json()


@app.get("/health")
def health():
    return {"status": "ok", "app": APP_NAME}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = current_user(request)
    if user:
        return RedirectResponse("/dashboard", status_code=303)
    body = """
    <section class="panel">
      <p>PYTHON · TELEGRAM BOTLAR · WEB SAYTLAR</p>
      <h1>Kodingiz uchun yagona bulutli makon.</h1>
      <p>GitHub loyihalaringizni ulang va hosting ish jarayonini
      yagona boshqaruv panelidan nazorat qiling.</p>
      <a class="button" href="/register">Bepul boshlash</a>
      <a class="button secondary" href="/login">Kirish</a>
    </section>
    <div class="grid">
      <section class="panel"><h3>Python</h3><p>Python ilovalari uchun loyiha boshqaruvi.</p></section>
      <section class="panel"><h3>Telegram botlar</h3><p>Bot loyihalarini background worker sifatida joylash.</p></section>
      <section class="panel"><h3>Web hosting</h3><p>GitHub repozitoriyidan servis deploy qilish.</p></section>
    </div>
    """
    return page("Bosh sahifa", body)


@app.get("/register", response_class=HTMLResponse)
def register_page():
    return page("Ro‘yxatdan o‘tish", """
    <section class="panel"><h1>Akkaunt yaratish</h1>
    <form method="post">
      <label>Email</label><input name="email" type="email" required maxlength="254">
      <label>Parol (kamida 10 belgi)</label>
      <input name="password" type="password" required minlength="10" maxlength="128">
      <button>Ro‘yxatdan o‘tish</button>
    </form><p>Akkauntingiz bormi? <a href="/login">Kirish</a></p></section>
    """)


@app.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    if len(email) > 254 or "@" not in email:
        raise HTTPException(400, "Email manzilini tekshiring.")
    if len(password) < 10 or len(password) > 128:
        raise HTTPException(400, "Parol 10–128 belgi bo‘lishi kerak.")

    with SessionLocal() as db:
        if db.query(User).filter_by(email=email).first():
            raise HTTPException(409, "Bu email allaqachon ro‘yxatdan o‘tgan.")
        user = User(email=email, password_hash=password_hasher.hash(password))
        db.add(user)
        db.commit()
        db.refresh(user)
        request.session.clear()
        request.session["uid"] = user.id
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return page("Kirish", """
    <section class="panel"><h1>Qaytganingizdan xursandmiz</h1>
    <form method="post">
      <label>Email</label><input name="email" type="email" required>
      <label>Parol</label><input name="password" type="password" required>
      <button>Kirish</button>
    </form><p>Akkaunt yo‘qmi? <a href="/register">Ro‘yxatdan o‘tish</a></p></section>
    """)


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    with SessionLocal() as db:
        user = db.query(User).filter_by(email=email.strip().lower()).first()
        if not user or not password_hasher.verify(password, user.password_hash):
            raise HTTPException(401, "Email yoki parol noto‘g‘ri.")
        request.session.clear()
        request.session["uid"] = user.id
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = require_user(request)
    with SessionLocal() as db:
        count = db.query(Project).filter_by(owner_id=user.id).count()
    body = f"""
    <h1>Dashboard</h1>
    <p>Salom! {user.email}</p>
    <div class="grid">
      <section class="panel"><small>Sizning loyihalaringiz</small>
      <h1>{count}</h1><a href="/projects">Loyihalarni boshqarish →</a></section>
      <section class="panel"><h3>Yangi loyiha</h3>
      <p>GitHub repozitoriyidan servis yaratishni boshlang.</p>
      <a class="button" href="/projects/new">+ Loyiha yaratish</a></section>
      <section class="panel"><h3>Render holati</h3>
      <p>{"API kaliti sozlangan" if RENDER_API_KEY else "API kaliti kiritilmagan"}</p>
      <a href="/services">Render servislarini ko‘rish →</a></section>
    </div>
    """
    return page("Dashboard", body, user)


@app.get("/projects", response_class=HTMLResponse)
def projects(request: Request):
    user = require_user(request)
    with SessionLocal() as db:
        rows = db.query(Project).filter_by(owner_id=user.id).order_by(
            Project.id.desc()
        ).all()
        cards = "".join(
            f"""<section class="panel"><h3>{p.name}</h3>
            <p>Tur: {p.kind}</p><p><a href="{p.repo_url}">{p.repo_url}</a></p>
            <p>Render ID: {p.render_service_id or "Hali ulanmagan"}</p>
            <form action="/projects/{p.id}/deploy" method="post">
              <button>Deploy boshlash</button>
            </form></section>""" for p in rows
        )
    body = f"""
    <h1>Loyihalar</h1><p>Saqlangan loyihalaringiz.</p>
    <a class="button" href="/projects/new">+ Yangi loyiha</a>
    <div class="grid">{cards or '<section class="panel">Hali loyiha yo‘q.</section>'}</div>
    """
    return page("Loyihalar", body, user)


@app.get("/projects/new", response_class=HTMLResponse)
def new_project_page(request: Request):
    user = require_user(request)
    return page("Yangi loyiha", """
    <section class="panel"><h1>Loyiha yaratish</h1>
    <p>Hozircha GitHub’dagi repozitoriy manzilini ulaysiz.
    Repozitoriy Render orqali deploy qilinishi mumkin bo‘lishi kerak.</p>
    <form method="post">
      <label>Loyiha nomi</label><input name="name" required maxlength="80">
      <label>Loyiha turi</label>
      <select name="kind">
        <option value="website">Web sayt / Python web ilova</option>
        <option value="bot">Telegram bot (background worker)</option>
        <option value="static">Statik HTML sayt</option>
      </select>
      <label>GitHub HTTPS URL</label>
      <input name="repo_url" type="url" placeholder="https://github.com/user/repo" required>
      <button>Loyihani saqlash</button>
    </form></section>
    """, user)


@app.post("/projects/new")
def new_project(
    request: Request,
    name: str = Form(...),
    kind: str = Form(...),
    repo_url: str = Form(...),
):
    user = require_user(request)
    name = name.strip()
    if not name or len(name) > 80:
        raise HTTPException(400, "Loyiha nomi 1–80 belgi bo‘lishi kerak.")
    if kind not in {"website", "bot", "static"}:
        raise HTTPException(400, "Loyiha turi noto‘g‘ri.")
    repo_url = safe_repo_url(repo_url)

    with SessionLocal() as db:
        project = Project(
            owner_id=user.id,
            name=name,
            kind=kind,
            repo_url=repo_url,
        )
        db.add(project)
        db.commit()
    return RedirectResponse("/projects", status_code=303)


@app.get("/services", response_class=HTMLResponse)
async def services(request: Request):
    user = require_user(request)
    result = await render_request("GET", "/services")
    items = []
    for item in result:
        service = item.get("service", item)
        items.append(
            f"<section class='panel'><h3>{service.get('name', 'Nomsiz servis')}</h3>"
            f"<p>ID: {service.get('id', '—')}</p>"
            f"<p>Holat: {service.get('suspended', 'noma’lum')}</p></section>"
        )
    body = "<h1>Render servislaringiz</h1><div class='grid'>" + (
        "".join(items) or "<section class='panel'>Hozircha servis topilmadi.</section>"
    ) + "</div>"
    return page("Render servislar", body, user)


@app.post("/projects/{project_id}/deploy")
async def deploy_project(request: Request, project_id: int):
    user = require_user(request)

    with SessionLocal() as db:
        project = db.query(Project).filter_by(
            id=project_id, owner_id=user.id
        ).first()
        if not project:
            raise HTTPException(404, "Loyiha topilmadi.")

        service_id = project.render_service_id

    if not service_id:
        raise HTTPException(
            409,
            "Bu loyiha hali Render servisiga ulanmagan. Avval Render’da "
            "servis yarating va uning ID raqamini sozlang."
        )

    await render_request(
        "POST",
        f"/services/{service_id}/deploys",
        {"clearCache": "do_not_clear"},
    )
    return RedirectResponse("/projects", status_code=303)
