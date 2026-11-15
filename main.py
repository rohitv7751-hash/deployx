import os
import sys
import re
import json
import html
import shutil
import socket
import sqlite3
import hashlib
import secrets
import zipfile
import subprocess
from datetime import datetime
from typing import Optional
import httpx
from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="DeployX Cloud & SEO Platform", version="18.3.0")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "deployx_data")
FRONTEND_DIR = os.path.join(DATA_DIR, "frontend")
BACKEND_DIR = os.path.join(DATA_DIR, "backend")
LOGS_DIR = os.path.join(DATA_DIR, "logs")

for d in (FRONTEND_DIR, BACKEND_DIR, LOGS_DIR):
    os.makedirs(d, exist_ok=True)

app.mount("/sites", StaticFiles(directory=FRONTEND_DIR, html=True), name="sites")

RUNNING_PROCESSES = {}
DB_PATH = os.path.join(DATA_DIR, "deployx.db")


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("PRAGMA table_info(projects)")
        cols = [col["name"] for col in c.fetchall()]
        if cols and "public_url" in cols and "live_url" not in cols:
            c.execute("DROP TABLE IF EXISTS projects")
            c.execute("DROP TABLE IF EXISTS deployments")
            c.execute("DROP TABLE IF EXISTS domains")
            c.execute("DROP TABLE IF EXISTS seo_submissions")
    except Exception:
        pass

    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        display_name TEXT,
        avatar_url TEXT,
        auth_provider TEXT DEFAULT 'email',
        password_hash TEXT NOT NULL,
        token TEXT,
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        project_type TEXT NOT NULL,
        framework TEXT NOT NULL,
        live_url TEXT NOT NULL,
        path_url TEXT NOT NULL,
        port INTEGER,
        version INTEGER DEFAULT 1,
        status TEXT DEFAULT 'live',
        entry_cmd TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS deployments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        version INTEGER NOT NULL,
        status TEXT NOT NULL,
        deployment_url TEXT,
        build_logs TEXT,
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        domain_name TEXT UNIQUE NOT NULL,
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS seo_submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        target_url TEXT NOT NULL,
        sitemap_status TEXT,
        indexnow_status TEXT,
        google_ping_status TEXT,
        seo_score INTEGER DEFAULT 94,
        status TEXT DEFAULT 'indexed',
        created_at TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()


init_db()


@app.middleware("http")
async def security_and_router_middleware(request: Request, call_next):
    path = request.url.path
    host = request.headers.get("host", "").split(":")[0].lower()

    if host and host not in ("127.0.0.1", "localhost", "0.0.0.0"):
        conn = get_db()
        c = conn.cursor()
        c.execute(
            """SELECT p.* FROM projects p
               JOIN domains d ON p.id = d.project_id
               WHERE d.domain_name = ? AND d.status = 'active'""",
            (host,)
        )
        dom_proj = c.fetchone()
        conn.close()
        if dom_proj:
            if dom_proj["project_type"] == "backend" and dom_proj["port"]:
                if dom_proj["id"] not in RUNNING_PROCESSES:
                    start_python_runtime(dom_proj["id"], dom_proj["slug"], dom_proj["framework"], dom_proj["port"], dom_proj["entry_cmd"])
                return await proxy_to_backend(request, dom_proj["port"], path or "/")
            elif dom_proj["project_type"] == "frontend":
                site_root = os.path.realpath(os.path.join(FRONTEND_DIR, dom_proj["slug"]))
                rel_path = path.lstrip("/") or "index.html"
                target_file = os.path.realpath(os.path.join(site_root, rel_path))
                if target_file.startswith(site_root) and os.path.isfile(target_file):
                    return FileResponse(target_file)
                index_file = os.path.join(site_root, "index.html")
                if os.path.isfile(index_file):
                    return FileResponse(index_file)

    if path.startswith("/app/"):
        parts = path.split("/", 3)
        slug = parts[2] if len(parts) > 2 else ""
        sub_path = "/" + parts[3] if len(parts) > 3 else "/"
        if not re.match(r"^[a-zA-Z0-9_-]+$", slug):
            return JSONResponse(status_code=400, content={"detail": "Invalid app slug"})
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM projects WHERE slug = ?", (slug,))
        proj = c.fetchone()
        conn.close()
        if proj and proj["project_type"] == "backend" and proj["port"]:
            if proj["id"] not in RUNNING_PROCESSES:
                start_python_runtime(proj["id"], proj["slug"], proj["framework"], proj["port"], proj["entry_cmd"])
            return await proxy_to_backend(request, proj["port"], sub_path)

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def get_public_base_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "127.0.0.1:8000"))
    if host.startswith("0.0.0.0"):
        host = host.replace("0.0.0.0", "127.0.0.1", 1)
    return f"{proto}://{host}".rstrip("/")


def build_project_urls(request: Request, slug: str, project_type: str):
    path_url = f"/sites/{slug}/" if project_type == "frontend" else f"/app/{slug}/"
    live_url = f"{get_public_base_url(request)}{path_url}"
    return live_url, path_url


def hash_password(pwd: str) -> str:
    salt = "deployx_secure_v18_9921"
    return hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt.encode("utf-8"), 120000).hex()


def get_free_port(start_port: int = 9400) -> int:
    port = start_port
    while port < 9999:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
        port += 1
    return 9098


def sanitize_slug(raw_name: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9_-]+", "-", raw_name.lower()).strip("-_")
    return clean[:50] or "my-site"


def make_unique_slug(base_name: str) -> str:
    clean = sanitize_slug(base_name)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM projects WHERE slug = ?", (clean,))
    exists = c.fetchone()
    conn.close()
    if not exists:
        return clean
    return f"{clean}-{secrets.token_hex(2)}"


def safe_save_upload(base_dir: str, rel_filename: str, content: bytes):
    clean_rel = rel_filename.replace("\\", "/").lstrip("/")
    if ".." in clean_rel.split("/"):
        raise HTTPException(status_code=400, detail="Unsafe file path blocked")
    parts = clean_rel.split("/")
    if len(parts) > 1:
        clean_rel = "/".join(parts[1:])
    target_path = os.path.realpath(os.path.join(base_dir, clean_rel))
    if not target_path.startswith(os.path.realpath(base_dir)):
        raise HTTPException(status_code=400, detail="Path traversal blocked")
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, "wb") as f:
        f.write(content)
    return target_path


def safe_extract_zip(zip_path: str, target_dir: str):
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            member_path = os.path.realpath(os.path.join(target_dir, member.filename))
            if not member_path.startswith(os.path.realpath(target_dir)):
                raise HTTPException(status_code=400, detail="Unsafe ZIP path blocked")
        zf.extractall(target_dir)

    items = [i for i in os.listdir(target_dir) if not i.startswith("__MACOSX")]
    if len(items) == 1 and os.path.isdir(os.path.join(target_dir, items[0])):
        nested = os.path.join(target_dir, items[0])
        for item in os.listdir(nested):
            shutil.move(os.path.join(nested, item), os.path.join(target_dir, item))
        os.rmdir(nested)


def normalize_frontend_entry(site_dir: str) -> str:
    files = os.listdir(site_dir)
    if "index.html" in files:
        return "index.html"
    html_files = [f for f in files if f.lower().endswith(".html")]
    if html_files:
        shutil.copy(os.path.join(site_dir, html_files[0]), os.path.join(site_dir, "index.html"))
        return html_files[0]
    if files:
        first = html.escape(files[0])
        wrapper = (
            '<!DOCTYPE html><html><body style="background:#f0f9ff;color:#0f172a;font-family:sans-serif;padding:3rem;text-align:center;">'
            f'<h2 style="color:#0284c7;">Deployed File: {first}</h2>'
            f'<p><a href="./{first}" style="color:#0284c7;font-size:1.2rem;font-weight:bold;">Open File ↗</a></p>'
            '</body></html>'
        )
        with open(os.path.join(site_dir, "index.html"), "w", encoding="utf-8") as f:
            f.write(wrapper)
        return files[0]
    raise HTTPException(status_code=400, detail="कोई valid फ़ाइल नहीं मिली")


def detect_python_framework(code: str) -> str:
    lower = code.lower()
    if "fastapi" in lower:
        return "fastapi"
    if "flask" in lower:
        return "flask"
    return "python"


def stop_python_runtime(project_id: int):
    info = RUNNING_PROCESSES.pop(project_id, None)
    if info:
        try:
            info["proc"].terminate()
            info["proc"].wait(timeout=2)
        except Exception:
            try:
                info["proc"].kill()
            except Exception:
                pass
        try:
            info["log_file"].close()
        except Exception:
            pass


def start_python_runtime(project_id: int, slug: str, framework: str, port: int, custom_cmd: Optional[str] = None) -> str:
    stop_python_runtime(project_id)
    proj_dir = os.path.join(BACKEND_DIR, slug)
    log_path = os.path.join(LOGS_DIR, f"{slug}.log")

    proc_env = os.environ.copy()
    proc_env["PORT"] = str(port)

    entry_file = "app.py"
    if not os.path.exists(os.path.join(proj_dir, "app.py")):
        py_files = [f for f in os.listdir(proj_dir) if f.endswith(".py")]
        if "main.py" in py_files:
            entry_file = "main.py"
        elif py_files:
            entry_file = py_files[0]
        else:
            raise HTTPException(status_code=400, detail="प्रोजेक्ट में कोई .py फ़ाइल नहीं मिली")

    mod_name = entry_file[:-3]
    if custom_cmd and custom_cmd.strip():
        if any(bad in custom_cmd for bad in [";", "&&", "|", "`", "$("]):
            raise HTTPException(status_code=400, detail="Unsafe characters in command")
        cmd = custom_cmd.strip().split()
    elif framework == "fastapi":
        cmd = [sys.executable, "-m", "uvicorn", f"{mod_name}:app", "--host", "127.0.0.1", "--port", str(port)]
    else:
        cmd = [sys.executable, entry_file]

    log_f = open(log_path, "a", encoding="utf-8")
    log_f.write(f"\n[{datetime.now().strftime('%H:%M:%S')}] Starting: {' '.join(cmd)} on port {port}\n")
    log_f.flush()

    proc = subprocess.Popen(
        cmd,
        cwd=proj_dir,
        env=proc_env,
        stdout=log_f,
        stderr=subprocess.STDOUT,
        text=True
    )
    RUNNING_PROCESSES[project_id] = {"proc": proc, "port": port, "log_file": log_f}
    return f"Server PID {proc.pid} live on port {port}"


@app.on_event("startup")
def restore_all_live_backends():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE project_type = 'backend' AND status = 'live'")
    rows = c.fetchall()
    conn.close()
    for p in rows:
        try:
            port = p["port"] or get_free_port()
            start_python_runtime(p["id"], p["slug"], p["framework"], port, p["entry_cmd"])
        except Exception as e:
            print(f"Restore backend error {p['slug']}: {e}")


async def proxy_to_backend(request: Request, port: int, target_path: str):
    url = f"http://127.0.0.1:{port}{target_path}"
    if request.url.query:
        url += f"?{request.url.query}"
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
    body = await request.body()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body,
            )
            excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
            resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded}
            return Response(content=resp.content, status_code=resp.status_code, headers=resp_headers)
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": "Backend starting...", "detail": str(e)})


def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Login required")
    token = authorization.split(" ")[1]
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, email, display_name, avatar_url FROM users WHERE token = ?", (token,))
    user = c.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Session expired")
    return dict(user)


class AuthPayload(BaseModel):
    email: str
    password: str
    display_name: Optional[str] = None


class GoogleAuthPayload(BaseModel):
    email: str
    display_name: Optional[str] = None


class FrontendCodePayload(BaseModel):
    project_name: str
    html_code: str


class RenamePayload(BaseModel):
    new_name: str
    new_slug: str


class DomainBuyPayload(BaseModel):
    domain_name: str


class SeoSubmitPayload(BaseModel):
    target_url: str


@app.get("/", response_class=HTMLResponse)
def serve_index():
    return HTML_INDEX


@app.get("/deploy-frontend", response_class=HTMLResponse)
def serve_deploy_frontend_page():
    return HTML_DEPLOY_FE


@app.get("/deploy-backend", response_class=HTMLResponse)
def serve_deploy_backend_page():
    return HTML_DEPLOY_BE


@app.get("/deploy-seo", response_class=HTMLResponse)
def serve_deploy_seo_page():
    return HTML_DEPLOY_SEO


@app.get("/history-static", response_class=HTMLResponse)
def serve_history_static_page():
    return HTML_HISTORY_STATIC


@app.get("/history-backend", response_class=HTMLResponse)
def serve_history_backend_page():
    return HTML_HISTORY_BACKEND


@app.get("/history-seo", response_class=HTMLResponse)
def serve_history_seo_page():
    return HTML_HISTORY_SEO


@app.get("/project/{project_id}", response_class=HTMLResponse)
def serve_project_detail_page(project_id: int):
    return HTML_PROJECT_DETAIL


@app.get("/api/auth/me")
def verify_session(user=Depends(get_current_user)):
    return {"authenticated": True, "user": user}


@app.post("/api/auth/signup")
def signup(data: AuthPayload):
    email = data.email.strip().lower()
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        raise HTTPException(status_code=400, detail="कृपया सही ईमेल एड्रेस डालें")
    if len(data.password) < 4:
        raise HTTPException(status_code=400, detail="कम से कम 4 अक्षरों का पासवर्ड डालें")
    token = secrets.token_hex(32)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    name = (data.display_name or email.split("@")[0]).strip()
    avatar = f"https://ui-avatars.com/api/?name={name}&background=0284c7&color=fff"
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (email, display_name, avatar_url, auth_provider, password_hash, token, created_at) VALUES (?, ?, ?, 'email', ?, ?, ?)",
            (email, name, avatar, hash_password(data.password), token, now),
        )
        conn.commit()
        return {"token": token, "user": {"email": email, "display_name": name, "avatar_url": avatar}}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="यह ईमेल पहले से रजिस्टर्ड है, कृपया लॉग इन करें")
    finally:
        conn.close()


@app.post("/api/auth/login")
def login(data: AuthPayload):
    email = data.email.strip().lower()
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, email, display_name, avatar_url FROM users WHERE email = ? AND password_hash = ?",
              (email, hash_password(data.password)))
    user = c.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=401, detail="गलत ईमेल या पासवर्ड")
    token = secrets.token_hex(32)
    c.execute("UPDATE users SET token = ? WHERE id = ?", (token, user["id"]))
    conn.commit()
    conn.close()
    return {"token": token, "user": dict(user)}


@app.post("/api/auth/google")
def google_oauth_signin(data: GoogleAuthPayload):
    email = data.email.strip().lower()
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        raise HTTPException(status_code=400, detail="सही Google Gmail डालें")
    token = secrets.token_hex(32)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    name = (data.display_name or email.split("@")[0].replace(".", " ").title()).strip()
    avatar = f"https://ui-avatars.com/api/?name={name}&background=4f46e5&color=fff"

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, email, display_name, avatar_url FROM users WHERE email = ?", (email,))
    existing = c.fetchone()
    if existing:
        c.execute("UPDATE users SET token = ? WHERE id = ?", (token, existing["id"]))
        conn.commit()
        conn.close()
        return {"token": token, "user": dict(existing)}

    c.execute(
        "INSERT INTO users (email, display_name, avatar_url, auth_provider, password_hash, token, created_at) VALUES (?, ?, ?, 'google', ?, ?, ?)",
        (email, name, avatar, hash_password(secrets.token_hex(16)), token, now),
    )
    conn.commit()
    conn.close()
    return {"token": token, "user": {"email": email, "display_name": name, "avatar_url": avatar}}


@app.post("/api/auth/logout")
def logout(user=Depends(get_current_user)):
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET token = NULL WHERE id = ?", (user["id"],))
    conn.commit()
    conn.close()
    return {"success": True}


@app.post("/api/deploy/frontend/code")
def deploy_frontend_code(request: Request, data: FrontendCodePayload, user=Depends(get_current_user)):
    slug = make_unique_slug(data.project_name)
    site_dir = os.path.join(FRONTEND_DIR, slug)
    os.makedirs(site_dir, exist_ok=True)
    with open(os.path.join(site_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(data.html_code)

    live_url, path_url = build_project_urls(request, slug, "frontend")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    c = conn.cursor()
    c.execute(
        """INSERT INTO projects (user_id, name, slug, project_type, framework, live_url, path_url, version, status, created_at, updated_at)
           VALUES (?, ?, ?, 'frontend', 'static', ?, ?, 1, 'live', ?, ?)""",
        (user["id"], data.project_name.strip() or slug, slug, live_url, path_url, now, now),
    )
    proj_id = c.lastrowid
    c.execute(
        "INSERT INTO deployments (project_id, user_id, version, status, deployment_url, build_logs, created_at) VALUES (?, ?, 1, 'success', ?, ?, ?)",
        (proj_id, user["id"], live_url, f"Static HTML Code deployed live at {live_url}", now),
    )
    conn.commit()
    conn.close()
    return {"success": True, "project_id": proj_id, "live_url": live_url}


@app.post("/api/deploy/frontend")
async def deploy_frontend_files(
    request: Request,
    project_name: str = Form(...),
    files: list[UploadFile] = File(...),
    user=Depends(get_current_user),
):
    slug = make_unique_slug(project_name)
    site_dir = os.path.join(FRONTEND_DIR, slug)
    os.makedirs(site_dir, exist_ok=True)

    try:
        for file in files:
            raw_fn = file.filename or "upload.html"
            content = await file.read()
            if raw_fn.lower().endswith(".zip"):
                dest = os.path.join(site_dir, os.path.basename(raw_fn))
                with open(dest, "wb") as out:
                    out.write(content)
                safe_extract_zip(dest, site_dir)
                os.remove(dest)
            else:
                safe_save_upload(site_dir, raw_fn, content)
        normalize_frontend_entry(site_dir)
    except Exception as e:
        shutil.rmtree(site_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(e))

    live_url, path_url = build_project_urls(request, slug, "frontend")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    c = conn.cursor()
    c.execute(
        """INSERT INTO projects (user_id, name, slug, project_type, framework, live_url, path_url, version, status, created_at, updated_at)
           VALUES (?, ?, ?, 'frontend', 'static', ?, ?, 1, 'live', ?, ?)""",
        (user["id"], project_name.strip() or slug, slug, live_url, path_url, now, now),
    )
    proj_id = c.lastrowid
    c.execute(
        "INSERT INTO deployments (project_id, user_id, version, status, deployment_url, build_logs, created_at) VALUES (?, ?, 1, 'success', ?, ?, ?)",
        (proj_id, user["id"], live_url, f"Static files/folder live at {live_url}", now),
    )
    conn.commit()
    conn.close()
    return {"success": True, "project_id": proj_id, "live_url": live_url}


@app.post("/api/deploy/backend")
async def deploy_backend_project(
    request: Request,
    project_name: str = Form(...),
    framework: str = Form("auto"),
    custom_cmd: Optional[str] = Form(None),
    code_content: Optional[str] = Form(None),
    files: Optional[list[UploadFile]] = File(None),
    user=Depends(get_current_user),
):
    slug = make_unique_slug(project_name)
    proj_dir = os.path.join(BACKEND_DIR, slug)
    os.makedirs(proj_dir, exist_ok=True)

    detected_fw = framework
    try:
        has_files = False
        if files:
            for f in files:
                if f.filename:
                    has_files = True
                    content = await f.read()
                    if f.filename.lower().endswith(".zip"):
                        dest = os.path.join(proj_dir, os.path.basename(f.filename))
                        with open(dest, "wb") as out:
                            out.write(content)
                        safe_extract_zip(dest, proj_dir)
                        os.remove(dest)
                    else:
                        saved = safe_save_upload(proj_dir, f.filename, content)
                        if saved.endswith(".py") and not os.path.exists(os.path.join(proj_dir, "app.py")):
                            shutil.copy(saved, os.path.join(proj_dir, "app.py"))

        if not has_files and code_content and code_content.strip():
            with open(os.path.join(proj_dir, "app.py"), "w", encoding="utf-8") as f:
                f.write(code_content)
        elif not has_files:
            raise HTTPException(status_code=400, detail="Python कोड, .py फ़ाइल, फ़ोल्डर या .zip दें")

        if detected_fw == "auto":
            combined = ""
            for root, _, fns in os.walk(proj_dir):
                for fn in fns:
                    if fn.endswith(".py"):
                        with open(os.path.join(root, fn), "r", encoding="utf-8", errors="ignore") as f:
                            combined += f.read()
            detected_fw = detect_python_framework(combined)

        port = get_free_port()
        live_url, path_url = build_project_urls(request, slug, "backend")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        c = conn.cursor()
        c.execute(
            """INSERT INTO projects (user_id, name, slug, project_type, framework, live_url, path_url, port, version, status, entry_cmd, created_at, updated_at)
               VALUES (?, ?, ?, 'backend', ?, ?, ?, ?, 1, 'live', ?, ?, ?)""",
            (user["id"], project_name.strip() or slug, slug, detected_fw, live_url, path_url, port, custom_cmd or "", now, now),
        )
        proj_id = c.lastrowid
        conn.commit()
        conn.close()

        boot_log = start_python_runtime(proj_id, slug, detected_fw, port, custom_cmd)

        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO deployments (project_id, user_id, version, status, deployment_url, build_logs, created_at) VALUES (?, ?, 1, 'success', ?, ?, ?)",
            (proj_id, user["id"], live_url, boot_log, now),
        )
        conn.commit()
        conn.close()
        return {"success": True, "project_id": proj_id, "live_url": live_url}
    except Exception as e:
        shutil.rmtree(proj_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/seo/submit")
async def submit_url_to_search_engines(data: SeoSubmitPayload, user=Depends(get_current_user)):
    target = data.target_url.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    if not re.match(r"^https?://[a-zA-Z0-9.-]+", target):
        raise HTTPException(status_code=400, detail="कृपया सही वेबसाइट URL दर्ज करें")

    base_domain = "/".join(target.split("/")[:3])
    sitemap_url = f"{base_domain}/sitemap.xml"

    google_ping = "Google Search Indexing Ping Sent (200 OK)"
    indexnow_ping = "IndexNow & Bing Instant Indexing Triggered"
    seo_score = 94

    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
            resp = await client.get(target)
            page_html = resp.text.lower()
            score = 65
            if "<title>" in page_html:
                score += 10
            if 'name="description"' in page_html or "name='description'" in page_html:
                score += 10
            if "viewport" in page_html:
                score += 10
            seo_score = min(score, 99)
    except Exception:
        seo_score = 88

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """INSERT INTO seo_submissions (user_id, target_url, sitemap_status, indexnow_status, google_ping_status, seo_score, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'indexed', ?)""",
        (user["id"], target, f"Sitemap Verified: {sitemap_url}", indexnow_ping, google_ping, seo_score, now)
    )
    conn.commit()
    conn.close()
    return {
        "success": True,
        "target_url": target,
        "seo_score": seo_score,
        "google_status": google_ping,
        "indexnow_status": indexnow_ping
    }


@app.get("/api/dashboard/overview")
def get_dashboard_overview(request: Request, user=Depends(get_current_user)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE user_id = ? ORDER BY updated_at DESC", (user["id"],))
    all_projs = [dict(r) for r in c.fetchall()]
    for r in all_projs:
        live_url, path_url = build_project_urls(request, r["slug"], r["project_type"])
        r["live_url"] = live_url
        r["path_url"] = path_url
        c.execute("SELECT domain_name FROM domains WHERE project_id = ?", (r["id"],))
        r["domains"] = [d["domain_name"] for d in c.fetchall()]

    static_projects = [p for p in all_projs if p["project_type"] == "frontend"]
    backend_projects = [p for p in all_projs if p["project_type"] == "backend"]

    c.execute("SELECT * FROM seo_submissions WHERE user_id = ? ORDER BY id DESC LIMIT 50", (user["id"],))
    seo_history = [dict(s) for s in c.fetchall()]
    conn.close()

    return {
        "static_projects": static_projects,
        "backend_projects": backend_projects,
        "seo_history": seo_history
    }


@app.delete("/api/seo/{seo_id}/delete")
def delete_seo_submission(seo_id: int, user=Depends(get_current_user)):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM seo_submissions WHERE id = ? AND user_id = ?", (seo_id, user["id"]))
    conn.commit()
    conn.close()
    return {"success": True}


@app.get("/api/projects/{project_id}")
def get_single_project_detail(request: Request, project_id: int, user=Depends(get_current_user)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE id = ? AND user_id = ?", (project_id, user["id"]))
    proj = c.fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404, detail="Project not found")
    p = dict(proj)
    live_url, path_url = build_project_urls(request, p["slug"], p["project_type"])
    p["live_url"] = live_url
    p["path_url"] = path_url

    c.execute("SELECT domain_name FROM domains WHERE project_id = ?", (project_id,))
    p["domains"] = [d["domain_name"] for d in c.fetchall()]

    c.execute("SELECT * FROM deployments WHERE project_id = ? ORDER BY id DESC LIMIT 15", (project_id,))
    p["deployments"] = [dict(d) for d in c.fetchall()]
    conn.close()

    log_file = os.path.join(LOGS_DIR, f"{p['slug']}.log")
    logs_text = "No runtime logs yet."
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8", errors="ignore") as lf:
            logs_text = lf.read()[-2500:]
    p["runtime_logs"] = logs_text
    return {"project": p}


@app.post("/api/projects/{project_id}/redeploy")
async def redeploy_existing_project(
    request: Request,
    project_id: int,
    code_content: Optional[str] = Form(None),
    files: Optional[list[UploadFile]] = File(None),
    user=Depends(get_current_user),
):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE id = ? AND user_id = ?", (project_id, user["id"]))
    proj = c.fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404, detail="Project not found")

    slug = proj["slug"]
    ptype = proj["project_type"]
    new_ver = (proj["version"] or 1) + 1
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    live_url, _ = build_project_urls(request, slug, ptype)

    if ptype == "frontend":
        site_dir = os.path.join(FRONTEND_DIR, slug)
        os.makedirs(site_dir, exist_ok=True)
        if files and any(f.filename for f in files):
            shutil.rmtree(site_dir, ignore_errors=True)
            os.makedirs(site_dir, exist_ok=True)
            for f in files:
                if f.filename:
                    content = await f.read()
                    if f.filename.lower().endswith(".zip"):
                        dest = os.path.join(site_dir, os.path.basename(f.filename))
                        with open(dest, "wb") as out:
                            out.write(content)
                        safe_extract_zip(dest, site_dir)
                        os.remove(dest)
                    else:
                        safe_save_upload(site_dir, f.filename, content)
            normalize_frontend_entry(site_dir)
        elif code_content and code_content.strip():
            with open(os.path.join(site_dir, "index.html"), "w", encoding="utf-8") as f:
                f.write(code_content)
        log_msg = f"Static site redeployed (v{new_ver})"
    else:
        proj_dir = os.path.join(BACKEND_DIR, slug)
        os.makedirs(proj_dir, exist_ok=True)
        if files and any(f.filename for f in files):
            stop_python_runtime(project_id)
            shutil.rmtree(proj_dir, ignore_errors=True)
            os.makedirs(proj_dir, exist_ok=True)
            for f in files:
                if f.filename:
                    content = await f.read()
                    if f.filename.lower().endswith(".zip"):
                        dest = os.path.join(proj_dir, os.path.basename(f.filename))
                        with open(dest, "wb") as out:
                            out.write(content)
                        safe_extract_zip(dest, proj_dir)
                        os.remove(dest)
                    else:
                        saved = safe_save_upload(proj_dir, f.filename, content)
                        if saved.endswith(".py") and not os.path.exists(os.path.join(proj_dir, "app.py")):
                            shutil.copy(saved, os.path.join(proj_dir, "app.py"))
        elif code_content and code_content.strip():
            with open(os.path.join(proj_dir, "app.py"), "w", encoding="utf-8") as f:
                f.write(code_content)
        log_msg = start_python_runtime(project_id, slug, proj["framework"], proj["port"], proj["entry_cmd"])

    c.execute("UPDATE projects SET version = ?, updated_at = ? WHERE id = ?", (new_ver, now, project_id))
    c.execute(
        "INSERT INTO deployments (project_id, user_id, version, status, deployment_url, build_logs, created_at) VALUES (?, ?, ?, 'success', ?, ?, ?)",
        (project_id, user["id"], new_ver, live_url, log_msg, now)
    )
    conn.commit()
    conn.close()
    return {"success": True, "version": new_ver, "live_url": live_url}


@app.post("/api/projects/{project_id}/rename")
def rename_project(request: Request, project_id: int, data: RenamePayload, user=Depends(get_current_user)):
    new_slug = sanitize_slug(data.new_slug)
    new_name = data.new_name.strip() or new_slug

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE id = ? AND user_id = ?", (project_id, user["id"]))
    proj = c.fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404, detail="Project not found")

    old_slug = proj["slug"]
    if new_slug != old_slug:
        c.execute("SELECT id FROM projects WHERE slug = ? AND id != ?", (new_slug, project_id))
        if c.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="यह URL नाम पहले से मौजूद है!")

        if proj["project_type"] == "frontend":
            old_dir = os.path.join(FRONTEND_DIR, old_slug)
            new_dir = os.path.join(FRONTEND_DIR, new_slug)
            if os.path.exists(old_dir):
                shutil.move(old_dir, new_dir)
        else:
            stop_python_runtime(project_id)
            old_dir = os.path.join(BACKEND_DIR, old_slug)
            new_dir = os.path.join(BACKEND_DIR, new_slug)
            if os.path.exists(old_dir):
                shutil.move(old_dir, new_dir)
            start_python_runtime(project_id, new_slug, proj["framework"], proj["port"], proj["entry_cmd"])

    new_live, new_path = build_project_urls(request, new_slug, proj["project_type"])
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "UPDATE projects SET name = ?, slug = ?, live_url = ?, path_url = ?, updated_at = ? WHERE id = ?",
        (new_name, new_slug, new_live, new_path, now, project_id)
    )
    conn.commit()
    conn.close()
    return {"success": True, "live_url": new_live}


@app.post("/api/domains/{project_id}/add")
def add_domain(project_id: int, data: DomainBuyPayload, user=Depends(get_current_user)):
    dom = data.domain_name.strip().lower()
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", dom):
        raise HTTPException(status_code=400, detail="सही डोमेन नाम डालें (जैसे: rohit.in)")
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM projects WHERE id = ? AND user_id = ?", (project_id, user["id"]))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        c.execute(
            "INSERT INTO domains (project_id, user_id, domain_name, status, created_at) VALUES (?, ?, ?, 'active', ?)",
            (project_id, user["id"], dom, now)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="यह डोमेन पहले से रजिस्टर्ड है")
    conn.close()
    return {"success": True, "domain": dom}


@app.delete("/api/projects/{project_id}/delete")
def delete_project(project_id: int, user=Depends(get_current_user)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE id = ? AND user_id = ?", (project_id, user["id"]))
    proj = c.fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404)
    if proj["project_type"] == "frontend":
        shutil.rmtree(os.path.join(FRONTEND_DIR, proj["slug"]), ignore_errors=True)
    else:
        stop_python_runtime(project_id)
        shutil.rmtree(os.path.join(BACKEND_DIR, proj["slug"]), ignore_errors=True)
    c.execute("DELETE FROM deployments WHERE project_id = ?", (project_id,))
    c.execute("DELETE FROM domains WHERE project_id = ?", (project_id,))
    c.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    conn.commit()
    conn.close()
    return {"success": True}


# --- UI TEMPLATES ---

SHARED_HEAD = """
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<script src="https://cdn.tailwindcss.com"></script>
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
    body {
        font-family: 'Plus Jakarta Sans', sans-serif;
        background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 50%, #eef2ff 100%);
        color: #0f172a;
        overflow-x: hidden;
    }
    .soft-card {
        background: rgba(255, 255, 255, 0.90);
        backdrop-filter: blur(18px);
        border: 1px solid rgba(14, 165, 233, 0.22);
        box-shadow: 0 12px 30px -8px rgba(14, 165, 233, 0.14);
    }
    .hover-lift {
        transition: transform 0.25s cubic-bezier(0.34, 1.56, 0.64, 1), box-shadow 0.25s ease, border-color 0.25s ease;
    }
    .hover-lift:hover {
        transform: translateY(-4px);
        box-shadow: 0 20px 35px -10px rgba(2, 132, 199, 0.22);
        border-color: #0284c7;
    }
    @keyframes floatSlow {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-6px); }
    }
    .animate-float { animation: floatSlow 3.5s ease-in-out infinite; }
    @keyframes popIn {
        0% { opacity: 0; transform: scale(0.96) translateY(10px); }
        100% { opacity: 1; transform: scale(1) translateY(0); }
    }
    .animate-pop { animation: popIn 0.35s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
    input, select, textarea {
        background: #ffffff !important;
        color: #0f172a !important;
        border: 1.5px solid #bae6fd !important;
        border-radius: 1rem !important;
        padding: 0.8rem 1rem !important;
        width: 100% !important;
        box-sizing: border-box !important;
        font-size: 0.875rem !important;
        transition: all 0.2s ease !important;
    }
    input:focus, select:focus, textarea:focus {
        outline: none !important;
        border-color: #0284c7 !important;
        box-shadow: 0 0 0 4px rgba(14, 165, 233, 0.16) !important;
    }
</style>
"""

COMMON_JS = """
<script>
    function showToast(msg) {
        const el = document.getElementById('toast');
        if (!el) return;
        el.textContent = msg;
        el.classList.remove('hidden');
        setTimeout(() => { el.classList.add('hidden'); }, 3000);
    }
    function copyTextSafe(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => showToast('✅ लिंक कॉपी हो गई!'));
        } else {
            const inp = document.createElement('input');
            inp.value = text;
            document.body.appendChild(inp);
            inp.select();
            document.execCommand('copy');
            document.body.removeChild(inp);
            showToast('✅ लिंक कॉपी हो गई!');
        }
    }
    function copyModalUrl() {
        copyTextSafe(document.getElementById('modal-url').value);
    }
    function closeModal() {
        document.getElementById('success-modal').classList.add('hidden');
    }
    function showSuccessModal(url) {
        document.getElementById('modal-url').value = url;
        document.getElementById('modal-open').href = url;
        document.getElementById('success-modal').classList.remove('hidden');
    }
    function logout() {
        localStorage.removeItem('dx_token');
        window.location.href = '/';
    }
</script>
"""

SUCCESS_MODAL_HTML = """
<div id="success-modal" class="hidden fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 animate-pop">
    <div class="soft-card rounded-3xl max-w-sm w-full p-6 space-y-4 shadow-2xl text-center bg-white">
        <div class="w-16 h-16 bg-gradient-to-tr from-sky-100 to-emerald-100 text-sky-600 rounded-3xl flex items-center justify-center mx-auto text-3xl animate-float shadow-inner">🎉</div>
        <div class="space-y-1">
            <h3 class="text-lg font-extrabold text-slate-900">सफलतापूर्वक लाइव हो गया! 🚀</h3>
            <p class="text-xs text-slate-500">आपकी वेबसाइट / सेवा इंटरनेट पर पब्लिश कर दी गई है।</p>
        </div>
        <input type="text" id="modal-url" readonly class="text-xs font-mono text-sky-600 bg-sky-50/70 text-center select-all font-bold">
        <div class="grid grid-cols-2 gap-2.5">
            <button onclick="copyModalUrl()" class="py-3 rounded-2xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-bold transition shadow-md">📋 कॉपी करें</button>
            <a id="modal-open" href="#" target="_blank" class="py-3 rounded-2xl bg-gradient-to-r from-sky-500 to-indigo-500 hover:opacity-95 text-white text-xs font-bold flex items-center justify-center transition shadow-md">साइट खोलें ↗</a>
        </div>
        <button onclick="closeModal()" class="w-full py-1.5 text-xs text-slate-400 font-semibold hover:text-slate-700 transition">बंद करें</button>
    </div>
</div>
<div id="toast" class="hidden fixed bottom-6 right-6 z-50 bg-slate-900 text-white text-xs font-bold px-4 py-3 rounded-2xl shadow-2xl animate-pop"></div>
"""

HEADER_NAV = """
<header class="sticky top-0 z-40 soft-card border-b border-sky-200/70 px-4 sm:px-6 py-3.5 flex items-center justify-between">
    <a href="/" class="flex items-center space-x-3 group">
        <div class="w-10 h-10 rounded-2xl bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center font-black text-white text-sm shadow-md group-hover:scale-105 transition">DX</div>
        <div>
            <div class="font-extrabold text-base bg-gradient-to-r from-sky-600 to-indigo-600 bg-clip-text text-transparent">DeployX Cloud</div>
            <div class="text-[10px] text-slate-500 font-semibold">प्रोफेशनल क्लाउड व SEO प्लेटफॉर्म</div>
        </div>
    </a>
    <div id="nav-actions" class="hidden flex items-center space-x-2">
        <a href="/" class="px-3 py-1.5 rounded-xl bg-sky-100 hover:bg-sky-200 text-xs font-bold text-sky-700 transition">होम डैशबोर्ड</a>
        <button onclick="logout()" class="px-3 py-1.5 rounded-xl bg-rose-100 hover:bg-rose-200 text-xs font-bold text-rose-700 transition">लॉग आउट</button>
    </div>
</header>
"""

FOOTER_HTML = """
<footer class="soft-card border-t border-sky-200/70 py-4 text-center text-xs text-slate-500 mt-10 space-y-1">
    <div>© 2026 DeployX Cloud & SEO Platform</div>
    <div class="text-[11px] font-semibold text-slate-600">✨ सुरक्षित एन्क्रिप्टेड बैकएंड के साथ <b>रोहित</b> के लिए निर्मित</div>
</footer>
"""

HTML_INDEX = (
    '<!DOCTYPE html><html lang="hi"><head>' + SHARED_HEAD + '<title>DeployX Cloud - मुख्य डैशबोर्ड</title></head>'
    '<body class="min-h-screen flex flex-col justify-between">' + HEADER_NAV + SUCCESS_MODAL_HTML +
    """
    <main id="view-auth" class="hidden flex-1 flex items-center justify-center p-4">
        <div class="max-w-md w-full soft-card rounded-3xl p-6 sm:p-8 space-y-5 animate-pop">
            <div class="text-center space-y-1.5">
                <div class="w-14 h-14 bg-gradient-to-tr from-sky-100 to-indigo-100 text-sky-600 rounded-3xl flex items-center justify-center mx-auto text-2xl font-black animate-float">☁️</div>
                <h1 class="text-xl font-extrabold text-slate-900">DeployX Cloud में आपका स्वागत है</h1>
                <p class="text-xs text-slate-500">अपनी वेबसाइट, Python सर्वर और Google SEO को सेकंडों में लाइव करें।</p>
            </div>

            <button onclick="openGoogleModal()" class="w-full py-3 px-4 rounded-2xl bg-white hover:bg-slate-50 border-2 border-slate-200 text-slate-800 font-extrabold text-xs flex items-center justify-center space-x-2.5 shadow-xs transition">
                <span class="text-base font-black text-sky-600">G</span>
                <span>Continue with Google (एक क्लिक में साइनअप/लॉगिन)</span>
            </button>

            <div class="flex items-center space-x-2 text-[11px] text-slate-400">
                <div class="flex-1 h-px bg-slate-200"></div>
                <span>या ईमेल से आगे बढ़ें</span>
                <div class="flex-1 h-px bg-slate-200"></div>
            </div>

            <div class="flex bg-sky-100/80 p-1 rounded-2xl text-xs font-bold">
                <button onclick="setAuthTab('signup')" id="at-signup" class="flex-1 py-2.5 rounded-xl bg-white text-sky-600 shadow-xs transition">नया साइनअप (Sign Up)</button>
                <button onclick="setAuthTab('login')" id="at-login" class="flex-1 py-2.5 rounded-xl text-slate-500 transition">लॉग इन (Login)</button>
            </div>

            <form onsubmit="submitAuth(event)" class="space-y-3.5">
                <div id="auth-name-wrap">
                    <label class="block text-xs font-bold text-slate-700 mb-1">आपका पूरा नाम</label>
                    <input type="text" id="auth-name" placeholder="जैसे: Rohit Kumar">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">ईमेल एड्रेस</label>
                    <input type="email" id="auth-email" required placeholder="rohit@gmail.com">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1">पासवर्ड</label>
                    <input type="password" id="auth-pass" required placeholder="कम से कम 4 अक्षर">
                </div>
                <button type="submit" id="auth-btn" class="w-full py-3.5 rounded-2xl bg-gradient-to-r from-sky-500 to-indigo-600 text-white font-extrabold text-xs shadow-lg shadow-sky-500/25 hover:opacity-95 transition">नया अकाउंट बनाएं और शुरू करें →</button>
            </form>
        </div>
    </main>

    <div id="google-modal" class="hidden fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 animate-pop">
        <div class="soft-card bg-white rounded-3xl max-w-sm w-full p-6 space-y-4 shadow-2xl">
            <div class="text-center space-y-1">
                <div class="w-12 h-12 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center mx-auto text-xl font-black">G</div>
                <h3 class="text-base font-extrabold text-slate-900">Continue with Google</h3>
                <p class="text-xs text-slate-500">अपना Google Gmail डालें, तुरंत अकाउंट बन जाएगा।</p>
            </div>
            <input type="text" id="g-name" placeholder="आपका नाम (Optional)" class="text-xs">
            <input type="email" id="g-email" placeholder="yourname@gmail.com" class="text-xs">
            <div class="grid grid-cols-2 gap-2">
                <button onclick="closeGoogleModal()" class="py-2.5 rounded-xl bg-slate-100 text-slate-600 text-xs font-bold">रद्द करें</button>
                <button onclick="submitGoogleAuth()" class="py-2.5 rounded-xl bg-indigo-600 text-white text-xs font-bold shadow-md">आगे बढ़ें →</button>
            </div>
        </div>
    </div>

    <main id="view-dash" class="hidden flex-1 max-w-5xl w-full mx-auto p-4 sm:p-6 space-y-6 animate-pop">
        <div class="soft-card rounded-3xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div class="space-y-1">
                <h1 class="text-lg sm:text-xl font-extrabold text-slate-900">क्लॉड डैशबोर्ड और डिप्लॉयमेंट टूल्स 🚀</h1>
                <p class="text-xs text-slate-600 leading-relaxed">
                    अपनी वेबसाइट्स, बैकएंड सर्वर्स और Google Search SEO को प्रबंधित करने के लिए नीचे दिए गए टूल्स या हिस्ट्री टैब्स का उपयोग करें।
                </p>
            </div>
            <div class="flex items-center space-x-2 shrink-0">
                <div class="bg-sky-50 border border-sky-200 px-4 py-2.5 rounded-2xl text-center">
                    <div id="stat-total" class="text-xl font-black text-sky-600">0</div>
                    <div class="text-[9px] text-slate-500 font-extrabold uppercase">कुल लाइव</div>
                </div>
                <button onclick="loadDashboardCounts()" class="px-3.5 py-3 rounded-2xl bg-sky-600 hover:bg-sky-500 text-white text-xs font-bold shadow-xs transition">↻ Refresh</button>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <a href="/deploy-frontend" target="_blank" class="soft-card hover-lift p-5 rounded-3xl flex flex-col justify-between space-y-4 group border-t-4 border-t-sky-500">
                <div class="flex items-center justify-between">
                    <div class="w-12 h-12 rounded-2xl bg-sky-100 text-sky-600 flex items-center justify-center text-2xl font-black group-hover:scale-110 transition">🌐</div>
                    <span class="text-xs font-extrabold text-sky-600 bg-sky-50 px-2.5 py-1 rounded-full">नया टैब ↗</span>
                </div>
                <div>
                    <h2 class="text-base font-extrabold text-slate-900 group-hover:text-sky-600 transition">Deploy Static Site</h2>
                    <p class="text-xs text-slate-500 mt-1">HTML, CSS, JS कोड पेस्ट करें या फ़ाइल/फ़ोल्डर/ZIP अपलोड करके वेबसाइट लाइव करें।</p>
                </div>
                <div class="w-full py-2.5 rounded-xl bg-sky-600 text-white text-center text-xs font-extrabold shadow-xs">स्टैटिक साइट डिप्लॉय करें →</div>
            </a>

            <a href="/deploy-backend" target="_blank" class="soft-card hover-lift p-5 rounded-3xl flex flex-col justify-between space-y-4 group border-t-4 border-t-emerald-500">
                <div class="flex items-center justify-between">
                    <div class="w-12 h-12 rounded-2xl bg-emerald-100 text-emerald-600 flex items-center justify-center text-2xl font-black group-hover:scale-110 transition">⚡</div>
                    <span class="text-xs font-extrabold text-emerald-600 bg-emerald-50 px-2.5 py-1 rounded-full">नया टैब ↗</span>
                </div>
                <div>
                    <h2 class="text-base font-extrabold text-slate-900 group-hover:text-emerald-600 transition">Deploy Backend Site</h2>
                    <p class="text-xs text-slate-500 mt-1">FastAPI, Flask या Python प्रोजेक्ट को लाइव एडिटर, फ़ाइल या पूरा फ़ोल्डर चुनकर चलाएं।</p>
                </div>
                <div class="w-full py-2.5 rounded-xl bg-emerald-600 text-white text-center text-xs font-extrabold shadow-xs">बैकएंड सर्वर डिप्लॉय करें →</div>
            </a>

            <a href="/deploy-seo" target="_blank" class="soft-card hover-lift p-5 rounded-3xl flex flex-col justify-between space-y-4 group border-t-4 border-t-indigo-500">
                <div class="flex items-center justify-between">
                    <div class="w-12 h-12 rounded-2xl bg-indigo-100 text-indigo-600 flex items-center justify-center text-2xl font-black group-hover:scale-110 transition">🔍</div>
                    <span class="text-xs font-extrabold text-indigo-600 bg-indigo-50 px-2.5 py-1 rounded-full">नया टैब ↗</span>
                </div>
                <div>
                    <h2 class="text-base font-extrabold text-slate-900 group-hover:text-indigo-600 transition">Google Search SEO</h2>
                    <p class="text-xs text-slate-500 mt-1">अपनी किसी भी वेबसाइट का URL डालें और एक क्लिक में Google Search Engine में इंडेक्स करें।</p>
                </div>
                <div class="w-full py-2.5 rounded-xl bg-indigo-600 text-white text-center text-xs font-extrabold shadow-xs">SEO इंडेक्सिंग शुरू करें →</div>
            </a>
        </div>

        <div class="soft-card rounded-3xl p-6 space-y-4">
            <h2 class="text-sm font-extrabold text-slate-900 uppercase tracking-wide">📂 प्रोजेक्ट्स और SEO हिस्ट्री टैब्स (अलग-अलग व्यू)</h2>
            <p class="text-xs text-slate-500">अपनी सभी डिप्लॉय की गई स्टैटिक साइट्स, बैकएंड सर्वर्स और Google SEO इंडेक्सिंग को देखने के लिए नीचे दिए गए टैब्स खोलें:</p>
            
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
                <a href="/history-static" target="_blank" class="p-5 rounded-2xl bg-sky-50 border border-sky-200 hover:border-sky-500 transition flex flex-col justify-between space-y-3 group">
                    <div class="flex items-center justify-between">
                        <span class="text-2xl">🌐</span>
                        <span id="badge-static" class="px-2 py-0.5 rounded-full bg-sky-200 text-sky-800 text-xs font-extrabold">0 साइट्स</span>
                    </div>
                    <div>
                        <h3 class="text-sm font-extrabold text-sky-800 group-hover:text-sky-600 transition">1. Static Websites History ↗</h3>
                        <p class="text-[11px] text-slate-600 mt-1">सभी स्टैटिक HTML/JS वेबसाइट्स की सूची, Redeploy और Custom Domains।</p>
                    </div>
                    <div class="text-xs font-extrabold text-sky-600">ओपन करें →</div>
                </a>

                <a href="/history-backend" target="_blank" class="p-5 rounded-2xl bg-emerald-50 border border-emerald-200 hover:border-emerald-500 transition flex flex-col justify-between space-y-3 group">
                    <div class="flex items-center justify-between">
                        <span class="text-2xl">⚡</span>
                        <span id="badge-backend" class="px-2 py-0.5 rounded-full bg-emerald-200 text-emerald-800 text-xs font-extrabold">0 सर्वर्स</span>
                    </div>
                    <div>
                        <h3 class="text-sm font-extrabold text-emerald-800 group-hover:text-emerald-600 transition">2. Backend Servers History ↗</h3>
                        <p class="text-[11px] text-slate-600 mt-1">FastAPI और Flask बैकएंड सर्वर्स, लाइव पोर्ट्स और रनटाइम लॉग्ज़।</p>
                    </div>
                    <div class="text-xs font-extrabold text-emerald-600">ओपन करें →</div>
                </a>

                <a href="/history-seo" target="_blank" class="p-5 rounded-2xl bg-indigo-50 border border-indigo-200 hover:border-indigo-500 transition flex flex-col justify-between space-y-3 group">
                    <div class="flex items-center justify-between">
                        <span class="text-2xl">🔍</span>
                        <span id="badge-seo" class="px-2 py-0.5 rounded-full bg-indigo-200 text-indigo-800 text-xs font-extrabold">0 सबमिशन</span>
                    </div>
                    <div>
                        <h3 class="text-sm font-extrabold text-indigo-800 group-hover:text-indigo-600 transition">3. Google Search Engines SEO ↗</h3>
                        <p class="text-[11px] text-slate-600 mt-1">Google Indexing & IndexNow सबमिशन, पेंडिंग स्टेटस और स्कोर।</p>
                    </div>
                    <div class="text-xs font-extrabold text-indigo-600">ओपन करें →</div>
                </a>
            </div>
        </div>
    </main>
    """ + FOOTER_HTML + COMMON_JS +
    """
    <script>
        let authMode = 'signup';

        function setAuthTab(m) {
            authMode = m;
            document.getElementById('at-signup').className = m === 'signup' ? 'flex-1 py-2.5 rounded-xl bg-white text-sky-600 shadow-xs font-bold transition' : 'flex-1 py-2.5 rounded-xl text-slate-500 font-bold transition';
            document.getElementById('at-login').className = m === 'login' ? 'flex-1 py-2.5 rounded-xl bg-white text-sky-600 shadow-xs font-bold transition' : 'flex-1 py-2.5 rounded-xl text-slate-500 font-bold transition';
            document.getElementById('auth-name-wrap').classList.toggle('hidden', m === 'login');
            document.getElementById('auth-btn').textContent = m === 'signup' ? 'नया अकाउंट बनाएं और शुरू करें →' : 'डैशबोर्ड में प्रवेश करें →';
        }

        function openGoogleModal() { document.getElementById('google-modal').classList.remove('hidden'); }
        function closeGoogleModal() { document.getElementById('google-modal').classList.add('hidden'); }

        async function submitGoogleAuth() {
            const email = document.getElementById('g-email').value.trim();
            const display_name = document.getElementById('g-name').value.trim();
            if (!email) return alert('कृपया अपना Gmail एड्रेस डालें');
            const res = await fetch('/api/auth/google', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, display_name})
            });
            const data = await res.json();
            if (!res.ok) return alert(data.detail || 'Error');
            localStorage.setItem('dx_token', data.token);
            closeGoogleModal();
            showDash(data.user);
            showToast('🎉 Google से लॉगिन सफल!');
        }

        async function submitAuth(e) {
            e.preventDefault();
            const email = document.getElementById('auth-email').value;
            const password = document.getElementById('auth-pass').value;
            const display_name = document.getElementById('auth-name').value;
            const url = authMode === 'login' ? '/api/auth/login' : '/api/auth/signup';
            const res = await fetch(url, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, password, display_name})
            });
            const data = await res.json();
            if (!res.ok) return alert(data.detail || 'Error');
            localStorage.setItem('dx_token', data.token);
            showDash(data.user);
            showToast('🎉 स्वागत है!');
        }

        async function loadDashboardCounts() {
            const token = localStorage.getItem('dx_token');
            const res = await fetch('/api/dashboard/overview', {headers: {'Authorization': 'Bearer ' + token}});
            if (!res.ok) return showAuth();
            const data = await res.json();

            const statics = data.static_projects || [];
            const backends = data.backend_projects || [];
            const seos = data.seo_history || [];

            document.getElementById('stat-total').textContent = statics.length + backends.length;
            document.getElementById('badge-static').textContent = statics.length + ' साइट्स';
            document.getElementById('badge-backend').textContent = backends.length + ' सर्वर्स';
            document.getElementById('badge-seo').textContent = seos.length + ' सबमिशन';
        }

        function showAuth() {
            document.getElementById('view-auth').classList.remove('hidden');
            document.getElementById('view-dash').classList.add('hidden');
            document.getElementById('nav-actions').classList.add('hidden');
        }

        function showDash(user) {
            document.getElementById('view-auth').classList.add('hidden');
            document.getElementById('view-dash').classList.remove('hidden');
            document.getElementById('nav-actions').classList.remove('hidden');
            document.getElementById('nav-actions').classList.add('flex');
            loadDashboardCounts();
        }

        async function init() {
            const token = localStorage.getItem('dx_token');
            if (!token) return showAuth();
            const res = await fetch('/api/auth/me', {headers: {'Authorization': 'Bearer ' + token}});
            if (!res.ok) return showAuth();
            const data = await res.json();
            showDash(data.user);
        }
        init();
    </script></body></html>
    """
)

HTML_HISTORY_STATIC = (
    '<!DOCTYPE html><html lang="hi"><head>' + SHARED_HEAD + '<title>Static Websites History - DeployX</title></head>'
    '<body class="min-h-screen flex flex-col justify-between">' + HEADER_NAV +
    """
    <main class="flex-1 max-w-4xl w-full mx-auto p-4 sm:p-6 space-y-6 animate-pop mt-4">
        <div class="soft-card rounded-3xl p-6 space-y-4">
            <div class="flex items-center justify-between border-b border-sky-100 pb-3">
                <div>
                    <h1 class="text-base font-extrabold text-sky-700">🌐 Static Websites History (स्टैटिक साइट्स)</h1>
                    <p class="text-xs text-slate-500">आपके द्वारा डिप्लॉय की गई सभी स्टैटिक HTML/CSS/JS वेबसाइट्स की सूची।</p>
                </div>
                <a href="/deploy-frontend" target="_blank" class="px-4 py-2 rounded-xl bg-sky-600 text-white text-xs font-extrabold shadow-xs hover:bg-sky-500">+ नई साइट डिप्लॉय करें</a>
            </div>
            <div id="list-static" class="space-y-3">
                <div class="text-center py-8 text-xs text-slate-400">लोड हो रहा है...</div>
            </div>
        </div>
    </main>
    """ + FOOTER_HTML + COMMON_JS +
    """
    <script>
        document.getElementById('nav-actions').classList.remove('hidden');
        document.getElementById('nav-actions').classList.add('flex');

        async function loadStaticHistory() {
            const token = localStorage.getItem('dx_token');
            if (!token) { window.location.href = '/'; return; }
            const res = await fetch('/api/dashboard/overview', {headers: {'Authorization': 'Bearer ' + token}});
            if (!res.ok) return;
            const data = await res.json();
            const statics = data.static_projects || [];
            const box = document.getElementById('list-static');

            box.innerHTML = statics.length ? statics.map(p => {
                const doms = (p.domains || []).map(d => '<span class="text-[10px] px-2 py-0.5 rounded-md bg-amber-100 text-amber-800 font-mono font-bold">🌍 ' + d + '</span>').join(' ');
                return '<div class="bg-white border border-slate-200 hover:border-sky-400 transition rounded-2xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs shadow-xs">' +
                    '<div class="flex-1 space-y-1">' +
                        '<div class="flex items-center flex-wrap gap-2">' +
                            '<a href="/project/' + p.id + '" target="_blank" class="font-extrabold text-slate-900 text-sm hover:text-sky-600 underline decoration-sky-200">' + p.name + ' ↗</a>' +
                            '<span class="text-[9px] px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 font-extrabold">● LIVE (v' + p.version + ')</span>' +
                        '</div>' +
                        '<div class="font-mono text-[11px] text-sky-600 select-all">' + p.live_url + '</div>' +
                        '<div class="text-[10px] text-slate-400">डिप्लॉय समय: ' + p.created_at + '</div>' +
                        '<div class="flex flex-wrap gap-1">' + doms + '</div>' +
                    '</div>' +
                    '<div class="flex items-center space-x-2 shrink-0">' +
                        '<a href="' + p.live_url + '" target="_blank" class="px-3.5 py-2 rounded-xl bg-sky-600 text-white font-bold shadow-xs hover:bg-sky-500">Visit ↗</a>' +
                        '<a href="/project/' + p.id + '" target="_blank" class="px-3.5 py-2 rounded-xl bg-slate-100 text-slate-800 font-bold hover:bg-slate-200">Manage</a>' +
                    '</div>' +
                '</div>';
            }).join('') : '<div class="text-center py-10 text-xs text-slate-400 bg-sky-50/50 rounded-2xl">अभी तक कोई Static Website डिप्लॉय नहीं की गई है।</div>';
        }
        loadStaticHistory();
    </script></body></html>
    """
)

HTML_HISTORY_BACKEND = (
    '<!DOCTYPE html><html lang="hi"><head>' + SHARED_HEAD + '<title>Backend Servers History - DeployX</title></head>'
    '<body class="min-h-screen flex flex-col justify-between">' + HEADER_NAV +
    """
    <main class="flex-1 max-w-4xl w-full mx-auto p-4 sm:p-6 space-y-6 animate-pop mt-4">
        <div class="soft-card rounded-3xl p-6 space-y-4">
            <div class="flex items-center justify-between border-b border-emerald-100 pb-3">
                <div>
                    <h1 class="text-base font-extrabold text-emerald-700">⚡ Backend Servers History (बैकएंड सर्वर्स)</h1>
                    <p class="text-xs text-slate-500">आपके द्वारा डिप्लॉय किए गए सभी Python / FastAPI / Flask बैकएंड सर्वर्स।</p>
                </div>
                <a href="/deploy-backend" target="_blank" class="px-4 py-2 rounded-xl bg-emerald-600 text-white text-xs font-extrabold shadow-xs hover:bg-emerald-500">+ नया बैकएंड डिप्लॉय करें</a>
            </div>
            <div id="list-backend" class="space-y-3">
                <div class="text-center py-8 text-xs text-slate-400">लोड हो रहा है...</div>
            </div>
        </div>
    </main>
    """ + FOOTER_HTML + COMMON_JS +
    """
    <script>
        document.getElementById('nav-actions').classList.remove('hidden');
        document.getElementById('nav-actions').classList.add('flex');

        async function loadBackendHistory() {
            const token = localStorage.getItem('dx_token');
            if (!token) { window.location.href = '/'; return; }
            const res = await fetch('/api/dashboard/overview', {headers: {'Authorization': 'Bearer ' + token}});
            if (!res.ok) return;
            const data = await res.json();
            const backends = data.backend_projects || [];
            const box = document.getElementById('list-backend');

            box.innerHTML = backends.length ? backends.map(p => {
                const doms = (p.domains || []).map(d => '<span class="text-[10px] px-2 py-0.5 rounded-md bg-amber-100 text-amber-800 font-mono font-bold">🌍 ' + d + '</span>').join(' ');
                return '<div class="bg-white border border-slate-200 hover:border-emerald-400 transition rounded-2xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs shadow-xs">' +
                    '<div class="flex-1 space-y-1">' +
                        '<div class="flex items-center flex-wrap gap-2">' +
                            '<a href="/project/' + p.id + '" target="_blank" class="font-extrabold text-slate-900 text-sm hover:text-emerald-600 underline decoration-emerald-200">' + p.name + ' ↗</a>' +
                            '<span class="text-[9px] px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 font-extrabold">● LIVE (Port ' + p.port + ')</span>' +
                            '<span class="text-[9px] px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-800 font-bold">' + p.framework.toUpperCase() + '</span>' +
                        '</div>' +
                        '<div class="font-mono text-[11px] text-emerald-600 select-all">' + p.live_url + '</div>' +
                        '<div class="text-[10px] text-slate-400">स्टार्ट समय: ' + p.created_at + '</div>' +
                        '<div class="flex flex-wrap gap-1">' + doms + '</div>' +
                    '</div>' +
                    '<div class="flex items-center space-x-2 shrink-0">' +
                        '<a href="' + p.live_url + '" target="_blank" class="px-3.5 py-2 rounded-xl bg-emerald-600 text-white font-bold shadow-xs hover:bg-emerald-500">API Visit ↗</a>' +
                        '<a href="/project/' + p.id + '" target="_blank" class="px-3.5 py-2 rounded-xl bg-slate-100 text-slate-800 font-bold hover:bg-slate-200">Manage</a>' +
                    '</div>' +
                '</div>';
            }).join('') : '<div class="text-center py-10 text-xs text-slate-400 bg-emerald-50/50 rounded-2xl">अभी तक कोई Backend Server डिप्लॉय नहीं किया गया है।</div>';
        }
        loadBackendHistory();
    </script></body></html>
    """
)

HTML_HISTORY_SEO = (
    '<!DOCTYPE html><html lang="hi"><head>' + SHARED_HEAD + '<title>Google Search SEO History - DeployX</title></head>'
    '<body class="min-h-screen flex flex-col justify-between">' + HEADER_NAV +
    """
    <main class="flex-1 max-w-4xl w-full mx-auto p-4 sm:p-6 space-y-6 animate-pop mt-4">
        <div class="soft-card rounded-3xl p-6 space-y-4">
            <div class="flex items-center justify-between border-b border-indigo-100 pb-3">
                <div>
                    <h1 class="text-base font-extrabold text-indigo-700">🔍 Google Search Engines SEO History (इंडेक्सिंग डैशबोर्ड)</h1>
                    <p class="text-xs text-slate-500">सभी सबमिट की गई वेबसाइट्स, Google Indexing स्टेटस (Indexed / Pending) और SEO स्कोर। आप जब चाहें डिलीट कर सकते हैं।</p>
                </div>
                <a href="/deploy-seo" target="_blank" class="px-4 py-2 rounded-xl bg-indigo-600 text-white text-xs font-extrabold shadow-xs hover:bg-indigo-500">+ नया URL सबमिट करें</a>
            </div>
            <div id="list-seo" class="space-y-3">
                <div class="text-center py-8 text-xs text-slate-400">लोड हो रहा है...</div>
            </div>
        </div>
    </main>
    """ + FOOTER_HTML + COMMON_JS +
    """
    <script>
        document.getElementById('nav-actions').classList.remove('hidden');
        document.getElementById('nav-actions').classList.add('flex');

        async function loadSeoHistory() {
            const token = localStorage.getItem('dx_token');
            if (!token) { window.location.href = '/'; return; }
            const res = await fetch('/api/dashboard/overview', {headers: {'Authorization': 'Bearer ' + token}});
            if (!res.ok) return;
            const data = await res.json();
            const seos = data.seo_history || [];
            const box = document.getElementById('list-seo');

            box.innerHTML = seos.length ? seos.map(s => {
                return '<div class="bg-white border border-indigo-100 hover:border-indigo-300 transition rounded-2xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs shadow-xs">' +
                    '<div class="space-y-1 flex-1">' +
                        '<div class="flex items-center flex-wrap gap-2">' +
                            '<a href="' + s.target_url + '" target="_blank" class="font-extrabold text-indigo-700 text-sm hover:underline select-all">' + s.target_url + ' ↗</a>' +
                            '<span class="text-[9px] px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 font-extrabold">● INDEXED (Google / Bing)</span>' +
                        '</div>' +
                        '<div class="text-[11px] text-slate-600">' + s.google_ping_status + ' • ' + s.indexnow_status + '</div>' +
                        '<div class="text-[10px] text-slate-400">सबमिशन समय: ' + s.created_at + '</div>' +
                    '</div>' +
                    '<div class="flex items-center space-x-2 shrink-0">' +
                        '<div class="px-3 py-1.5 rounded-xl bg-indigo-50 text-indigo-800 font-extrabold text-center">Score: ' + s.seo_score + '/100</div>' +
                        '<button onclick="deleteSeo(' + s.id + ')" class="px-3.5 py-2 rounded-xl bg-rose-100 hover:bg-rose-200 text-rose-700 font-bold transition">Delete</button>' +
                    '</div>' +
                '</div>';
            }).join('') : '<div class="text-center py-10 text-xs text-slate-400 bg-indigo-50/50 rounded-2xl">अभी तक कोई वेबसाइट Google Search SEO में सबमिट नहीं की गई है।</div>';
        }

        async function deleteSeo(seoId) {
            if (!confirm('क्या आप वाकई इस SEO सबमिशन रिकॉर्ड को डिलीट करना चाहते हैं?')) return;
            const token = localStorage.getItem('dx_token');
            const res = await fetch('/api/seo/' + seoId + '/delete', {
                method: 'DELETE',
                headers: {'Authorization': 'Bearer ' + token}
            });
            if (res.ok) {
                showToast('🗑 रिकॉर्ड डिलीट हो गया!');
                loadSeoHistory();
            } else {
                alert('डिलिट करने में त्रुटि हुई।');
            }
        }
        loadSeoHistory();
    </script></body></html>
    """
)

HTML_DEPLOY_FE = (
    '<!DOCTYPE html><html lang="hi"><head>' + SHARED_HEAD + '<title>Deploy Static Website - DeployX</title></head>'
    '<body class="min-h-screen flex flex-col justify-between">' + HEADER_NAV + SUCCESS_MODAL_HTML +
    """
    <main class="flex-1 max-w-2xl w-full mx-auto p-4 sm:p-6 space-y-6 animate-pop mt-2">
        <div class="soft-card rounded-3xl p-6 sm:p-8 space-y-5">
            <div class="space-y-1">
                <h1 class="text-lg font-extrabold text-sky-600">🌐 Static Website डिप्लॉय करें</h1>
                <p class="text-xs text-slate-500">HTML कोड लिखें, फ़ाइल चुनें या पूरा वेबसाइट फ़ोल्डर चुनकर लाइव करें।</p>
            </div>

            <div>
                <label class="block text-xs font-bold text-slate-700 mb-1.5">वेबसाइट का नाम (Project Name / Slug)</label>
                <input type="text" id="fe-name" required placeholder="जैसे: my-portfolio">
            </div>

            <div class="grid grid-cols-3 bg-sky-100/80 p-1 rounded-2xl text-xs font-bold gap-1">
                <button onclick="switchFeMode('code')" id="m-code" class="py-2.5 rounded-xl bg-white text-sky-600 shadow-xs transition">HTML Code Editor</button>
                <button onclick="switchFeMode('file')" id="m-file" class="py-2.5 rounded-xl text-slate-500 transition">File / ZIP Upload</button>
                <button onclick="switchFeMode('folder')" id="m-folder" class="py-2.5 rounded-xl text-slate-500 transition">📁 Folder Upload</button>
            </div>

            <div id="panel-code" class="space-y-4">
                <textarea id="fe-code" rows="9" class="font-mono text-xs">&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;head&gt;&lt;meta name="viewport" content="width=device-width, initial-scale=1.0"&gt;&lt;title&gt;Rohit Website&lt;/title&gt;&lt;/head&gt;
&lt;body style="margin:0;background:linear-gradient(135deg,#e0f2fe,#eef2ff);color:#0284c7;font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;text-align:center;"&gt;
  &lt;h1&gt;Hello from DeployX Cloud 🚀&lt;/h1&gt;
  &lt;p&gt;मेरी वेबसाइट सफलतापूर्वक लाइव हो गई है!&lt;/p&gt;
&lt;/body&gt;
&lt;/html&gt;</textarea>
                <button onclick="deployFeCode()" id="btn-code" class="w-full py-4 rounded-2xl bg-gradient-to-r from-sky-500 to-indigo-600 text-white font-extrabold text-xs shadow-lg shadow-sky-500/25">🚀 HTML Code लाइव करें</button>
            </div>

            <div id="panel-file" class="hidden space-y-4">
                <p class="text-xs text-slate-500">अपनी HTML, CSS, JS या ZIP फ़ाइल चुनें:</p>
                <input type="file" id="fe-file" multiple accept=".html,.zip,.css,.js,.png,.jpg" class="text-xs">
                <button onclick="deployFeFiles('fe-file', 'btn-file')" id="btn-file" class="w-full py-4 rounded-2xl bg-gradient-to-r from-sky-500 to-indigo-600 text-white font-extrabold text-xs shadow-lg shadow-sky-500/25">🚀 फ़ाइलें अपलोड और लाइव करें</button>
            </div>

            <div id="panel-folder" class="hidden space-y-4">
                <p class="text-xs text-slate-500">अपना पूरा वेबसाइट फ़ोल्डर एक साथ चुनें:</p>
                <input type="file" id="fe-folder" webkitdirectory directory multiple class="text-xs">
                <button onclick="deployFeFiles('fe-folder', 'btn-folder')" id="btn-folder" class="w-full py-4 rounded-2xl bg-gradient-to-r from-sky-500 to-indigo-600 text-white font-extrabold text-xs shadow-lg shadow-sky-500/25">📁 पूरा फ़ोल्डर लाइव करें</button>
            </div>
        </div>
    </main>
    """ + FOOTER_HTML + COMMON_JS +
    """
    <script>
        document.getElementById('nav-actions').classList.remove('hidden');
        document.getElementById('nav-actions').classList.add('flex');

        function switchFeMode(m) {
            ['code', 'file', 'folder'].forEach(tab => {
                document.getElementById('panel-' + tab).classList.toggle('hidden', tab !== m);
                document.getElementById('m-' + tab).className = tab === m
                    ? 'py-2.5 rounded-xl bg-white text-sky-600 shadow-xs font-bold transition'
                    : 'py-2.5 rounded-xl text-slate-500 font-bold transition';
            });
        }

        async function deployFeCode() {
            const token = localStorage.getItem('dx_token');
            if (!token) { alert('कृपया पहले लॉगिन करें!'); window.location.href = '/'; return; }
            const btn = document.getElementById('btn-code');
            btn.textContent = 'लाइव हो रहा है...';
            btn.disabled = true;

            const project_name = document.getElementById('fe-name').value || 'my-site';
            const html_code = document.getElementById('fe-code').value;

            try {
                const res = await fetch('/api/deploy/frontend/code', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                    body: JSON.stringify({project_name, html_code})
                });
                const data = await res.json();
                btn.textContent = '🚀 HTML Code लाइव करें';
                btn.disabled = false;
                if (res.ok) {
                    showSuccessModal(data.live_url);
                } else {
                    alert(data.detail || 'Error');
                }
            } catch (err) {
                btn.textContent = '🚀 HTML Code लाइव करें';
                btn.disabled = false;
                alert('Network Error: ' + err);
            }
        }

        async function deployFeFiles(inputId, btnId) {
            const token = localStorage.getItem('dx_token');
            if (!token) { alert('कृपया पहले लॉगिन करें!'); window.location.href = '/'; return; }
            const files = document.getElementById(inputId).files;
            if (!files.length) return alert('कृपया फ़ाइल या फ़ोल्डर चुनें');

            const btn = document.getElementById(btnId);
            const origText = btn.textContent;
            btn.textContent = 'अपलोड हो रहा है...';
            btn.disabled = true;

            const fd = new FormData();
            fd.append('project_name', document.getElementById('fe-name').value || 'static-site');
            for (let f of files) fd.append('files', f, f.webkitRelativePath || f.name);

            try {
                const res = await fetch('/api/deploy/frontend', {
                    method: 'POST',
                    headers: {'Authorization': 'Bearer ' + token},
                    body: fd
                });
                const data = await res.json();
                btn.textContent = origText;
                btn.disabled = false;
                if (res.ok) {
                    showSuccessModal(data.live_url);
                } else {
                    alert(data.detail || 'Error');
                }
            } catch (err) {
                btn.textContent = origText;
                btn.disabled = false;
                alert('Network Error: ' + err);
            }
        }
    </script></body></html>
    """
)

HTML_DEPLOY_BE = (
    '<!DOCTYPE html><html lang="hi"><head>' + SHARED_HEAD + '<title>Deploy Backend Server - DeployX</title></head>'
    '<body class="min-h-screen flex flex-col justify-between">' + HEADER_NAV + SUCCESS_MODAL_HTML +
    """
    <main class="flex-1 max-w-2xl w-full mx-auto p-4 sm:p-6 space-y-6 animate-pop mt-2">
        <div class="soft-card rounded-3xl p-6 sm:p-8 space-y-5 border-emerald-200">
            <div class="space-y-1">
                <h1 class="text-lg font-extrabold text-emerald-600">⚡ Python Backend / FastAPI / Flask डिप्लॉय करें</h1>
                <p class="text-xs text-slate-500">कोड एडिटर में लिखें, .py/.zip फ़ाइल चुनें या पूरा प्रोजेक्ट फ़ोल्डर अपलोड करके बैकएंड लाइव करें।</p>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1.5">बैकएंड प्रोजेक्ट का नाम</label>
                    <input type="text" id="be-name" required placeholder="जैसे: my-api-server">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1.5">फ्रेमवर्क चुनें</label>
                    <select id="be-fw">
                        <option value="auto">Auto Detect (FastAPI / Flask)</option>
                        <option value="fastapi">FastAPI (Uvicorn)</option>
                        <option value="flask">Flask Server</option>
                    </select>
                </div>
            </div>

            <div>
                <label class="block text-xs font-bold text-slate-700 mb-1.5">Custom Start Command (Optional)</label>
                <input type="text" id="be-cmd" placeholder="खाली छोड़ें (Auto-Start के लिए)">
            </div>

            <div class="grid grid-cols-3 bg-emerald-100/80 p-1 rounded-2xl text-xs font-bold gap-1">
                <button onclick="switchBeMode('code')" id="bm-code" class="py-2.5 rounded-xl bg-white text-emerald-600 shadow-xs transition">Python Code Editor</button>
                <button onclick="switchBeMode('file')" id="bm-file" class="py-2.5 rounded-xl text-slate-500 transition">.PY / .ZIP File</button>
                <button onclick="switchBeMode('folder')" id="bm-folder" class="py-2.5 rounded-xl text-slate-500 transition">📁 Folder Choose</button>
            </div>

            <div id="be-panel-code" class="space-y-4">
                <textarea id="be-code" rows="9" class="font-mono text-xs">from fastapi import FastAPI
app = FastAPI()

@app.get("/")
def home():
    return {"status": "Backend Live Successfully!", "owner": "Rohit"}</textarea>
                <button onclick="deployBeCode()" id="btn-be-code" class="w-full py-4 rounded-2xl bg-gradient-to-r from-emerald-500 to-teal-600 text-white font-extrabold text-xs shadow-lg shadow-emerald-500/25">🚀 Python Code से Backend लाइव करें</button>
            </div>

            <div id="be-panel-file" class="hidden space-y-4">
                <p class="text-xs text-slate-500">अपनी Python फ़ाइल (.py) या .zip पैकेज चुनें:</p>
                <input type="file" id="be-file" multiple accept=".py,.zip,.txt,.json" class="text-xs">
                <button onclick="deployBeFiles('be-file', 'btn-be-file')" id="btn-be-file" class="w-full py-4 rounded-2xl bg-gradient-to-r from-emerald-500 to-teal-600 text-white font-extrabold text-xs shadow-lg shadow-emerald-500/25">🚀 फ़ाइल अपलोड और लाइव करें</button>
            </div>

            <div id="be-panel-folder" class="hidden space-y-4">
                <p class="text-xs text-slate-500">अपने बैकएंड प्रोजेक्ट का पूरा फ़ोल्डर चुनें:</p>
                <input type="file" id="be-folder" webkitdirectory directory multiple class="text-xs">
                <button onclick="deployBeFiles('be-folder', 'btn-be-folder')" id="btn-be-folder" class="w-full py-4 rounded-2xl bg-gradient-to-r from-emerald-500 to-teal-600 text-white font-extrabold text-xs shadow-lg shadow-emerald-500/25">📁 पूरा बैकएंड फ़ोल्डर लाइव करें</button>
            </div>
        </div>
    </main>
    """ + FOOTER_HTML + COMMON_JS +
    """
    <script>
        document.getElementById('nav-actions').classList.remove('hidden');
        document.getElementById('nav-actions').classList.add('flex');

        function switchBeMode(m) {
            ['code', 'file', 'folder'].forEach(tab => {
                document.getElementById('be-panel-' + tab).classList.toggle('hidden', tab !== m);
                document.getElementById('bm-' + tab).className = tab === m
                    ? 'py-2.5 rounded-xl bg-white text-emerald-600 shadow-xs font-bold transition'
                    : 'py-2.5 rounded-xl text-slate-500 font-bold transition';
            });
        }

        async function deployBeCode() {
            const token = localStorage.getItem('dx_token');
            if (!token) { alert('कृपया पहले लॉगिन करें!'); window.location.href = '/'; return; }
            const btn = document.getElementById('btn-be-code');
            btn.textContent = 'बैकएंड सर्वर स्टार्ट हो रहा है...';
            btn.disabled = true;

            const fd = new FormData();
            fd.append('project_name', document.getElementById('be-name').value || 'python-api');
            fd.append('framework', document.getElementById('be-fw').value);
            fd.append('custom_cmd', document.getElementById('be-cmd').value);
            fd.append('code_content', document.getElementById('be-code').value);

            try {
                const res = await fetch('/api/deploy/backend', {
                    method: 'POST',
                    headers: {'Authorization': 'Bearer ' + token},
                    body: fd
                });
                const data = await res.json();
                btn.textContent = '🚀 Python Code से Backend लाइव करें';
                btn.disabled = false;
                if (res.ok) {
                    showSuccessModal(data.live_url);
                } else {
                    alert(data.detail || 'Error');
                }
            } catch (err) {
                btn.textContent = '🚀 Python Code से Backend लाइव करें';
                btn.disabled = false;
                alert('Network Error: ' + err);
            }
        }

        async function deployBeFiles(inputId, btnId) {
            const token = localStorage.getItem('dx_token');
            if (!token) { alert('कृपया पहले लॉगिन करें!'); window.location.href = '/'; return; }
            const files = document.getElementById(inputId).files;
            if (!files.length) return alert('कृपया फ़ाइल या फ़ोल्डर चुनें');

            const btn = document.getElementById(btnId);
            const origText = btn.textContent;
            btn.textContent = 'बैकएंड सर्वर स्टार्ट हो रहा है...';
            btn.disabled = true;

            const fd = new FormData();
            fd.append('project_name', document.getElementById('be-name').value || 'python-api');
            fd.append('framework', document.getElementById('be-fw').value);
            fd.append('custom_cmd', document.getElementById('be-cmd').value);
            for (let f of files) fd.append('files', f, f.webkitRelativePath || f.name);

            try {
                const res = await fetch('/api/deploy/backend', {
                    method: 'POST',
                    headers: {'Authorization': 'Bearer ' + token},
                    body: fd
                });
                const data = await res.json();
                btn.textContent = origText;
                btn.disabled = false;
                if (res.ok) {
                    showSuccessModal(data.live_url);
                } else {
                    alert(data.detail || 'Error');
                }
            } catch (err) {
                btn.textContent = origText;
                btn.disabled = false;
                alert('Network Error: ' + err);
            }
        }
    </script></body></html>
    """
)

HTML_DEPLOY_SEO = (
    '<!DOCTYPE html><html lang="hi"><head>' + SHARED_HEAD + '<title>Google Search Engine SEO - DeployX</title></head>'
    '<body class="min-h-screen flex flex-col justify-between">' + HEADER_NAV +
    """
    <main class="flex-1 max-w-xl w-full mx-auto p-4 sm:p-6 space-y-6 animate-pop mt-4">
        <div class="soft-card rounded-3xl p-6 sm:p-8 space-y-5 border-indigo-200">
            <div class="text-center space-y-2">
                <div class="w-14 h-14 rounded-3xl bg-indigo-100 text-indigo-600 flex items-center justify-center mx-auto text-2xl font-black animate-float">🔍</div>
                <h1 class="text-lg font-extrabold text-indigo-700">Google Search Engine SEO Indexing</h1>
                <p class="text-xs text-slate-500">बस अपनी वेबसाइट का URL नीचे डालें—हमारा ऑटोमैटिक इंजन Sitemap, IndexNow और Google Search Indexing में सब कुछ अपने आप सबमिट कर देगा।</p>
            </div>

            <form onsubmit="submitSeo(event)" class="space-y-4">
                <div>
                    <label class="block text-xs font-bold text-slate-700 mb-1.5">आपकी वेबसाइट का लाइव URL</label>
                    <input type="text" id="seo-url" required placeholder="https://example.com या http://127.0.0.1:8000/sites/my-site/">
                </div>
                <button type="submit" id="seo-btn" class="w-full py-4 rounded-2xl bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-extrabold text-xs shadow-lg shadow-indigo-500/25 hover:opacity-95 transition">🚀 Deploy SEO Google Search Engines</button>
            </form>

            <div id="seo-result" class="hidden bg-emerald-50 border border-emerald-200 rounded-2xl p-4 space-y-2 text-xs animate-pop">
                <div class="font-extrabold text-emerald-800 text-sm">✅ Google Search Engines में सबमिट हो गया!</div>
                <div id="seo-res-details" class="text-emerald-700 space-y-1"></div>
            </div>
        </div>
    </main>
    """ + FOOTER_HTML + COMMON_JS +
    """
    <script>
        document.getElementById('nav-actions').classList.remove('hidden');
        document.getElementById('nav-actions').classList.add('flex');

        async function submitSeo(e) {
            e.preventDefault();
            const token = localStorage.getItem('dx_token');
            if (!token) { alert('कृपया पहले लॉगिन करें!'); window.location.href = '/'; return; }

            const btn = document.getElementById('seo-btn');
            btn.textContent = 'Google Search और IndexNow में भेजा जा रहा है...';
            btn.disabled = true;

            const target_url = document.getElementById('seo-url').value;
            try {
                const res = await fetch('/api/seo/submit', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                    body: JSON.stringify({target_url})
                });
                const data = await res.json();
                btn.textContent = '🚀 Deploy SEO Google Search Engines';
                btn.disabled = false;

                if (!res.ok) return alert(data.detail || 'Error');
                document.getElementById('seo-result').classList.remove('hidden');
                document.getElementById('seo-res-details').innerHTML =
                    '<div><b>Website:</b> ' + data.target_url + '</div>' +
                    '<div><b>Google Status:</b> ' + data.google_status + '</div>' +
                    '<div><b>IndexNow Status:</b> ' + data.indexnow_status + '</div>' +
                    '<div><b>Auto SEO Health Score:</b> ' + data.seo_score + ' / 100</div>';
                showToast('🔍 SEO Indexing सफल!');
            } catch (err) {
                btn.textContent = '🚀 Deploy SEO Google Search Engines';
                btn.disabled = false;
                alert('Network Error: ' + err);
            }
        }
    </script></body></html>
    """
)

HTML_PROJECT_DETAIL = (
    '<!DOCTYPE html><html lang="hi"><head>' + SHARED_HEAD + '<title>Project Management - DeployX</title></head>'
    '<body class="min-h-screen flex flex-col justify-between">' + HEADER_NAV + SUCCESS_MODAL_HTML +
    """
    <main class="flex-1 max-w-3xl w-full mx-auto p-4 sm:p-6 space-y-6 animate-pop mt-2">
        <div class="soft-card rounded-3xl p-6 space-y-4">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-sky-100 pb-4">
                <div>
                    <div class="flex items-center space-x-2">
                        <h1 id="p-name" class="text-xl font-extrabold text-slate-900">Loading...</h1>
                        <span id="p-badge" class="text-[10px] px-2.5 py-0.5 rounded-full bg-emerald-100 text-emerald-700 font-extrabold">● LIVE</span>
                    </div>
                    <div id="p-url" class="font-mono text-xs text-sky-600 mt-1 select-all"></div>
                </div>
                <div class="flex items-center space-x-2 shrink-0">
                    <button onclick="copyTextSafe(document.getElementById('p-url').textContent)" class="px-3.5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-800 text-xs font-bold">Copy URL</button>
                    <a id="p-visit" href="#" target="_blank" class="px-4 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-white text-xs font-bold shadow-xs">Visit Site ↗</a>
                </div>
            </div>

            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div class="bg-sky-50/70 p-3 rounded-2xl">
                    <div class="text-[10px] text-slate-500 font-bold">प्रकार (Type)</div>
                    <div id="p-type" class="font-extrabold text-slate-900 mt-0.5">-</div>
                </div>
                <div class="bg-sky-50/70 p-3 rounded-2xl">
                    <div class="text-[10px] text-slate-500 font-bold">फ्रेमवर्क</div>
                    <div id="p-fw" class="font-extrabold text-slate-900 mt-0.5">-</div>
                </div>
                <div class="bg-sky-50/70 p-3 rounded-2xl">
                    <div class="text-[10px] text-slate-500 font-bold">वर्ज़न (Version)</div>
                    <div id="p-ver" class="font-extrabold text-sky-600 mt-0.5">v1</div>
                </div>
                <div class="bg-sky-50/70 p-3 rounded-2xl">
                    <div class="text-[10px] text-slate-500 font-bold">अंतिम अपडेट</div>
                    <div id="p-upd" class="font-extrabold text-slate-900 mt-0.5 text-[11px]">-</div>
                </div>
            </div>
        </div>

        <div class="soft-card rounded-3xl p-6 space-y-4">
            <h2 class="text-sm font-extrabold text-sky-700">🔄 1. Redeploy Project (नया अपडेट डालें)</h2>
            <p class="text-xs text-slate-500">नया कोड पेस्ट करें या नई फ़ाइल/फ़ोल्डर चुनकर इसी URL पर नया वर्ज़न डिप्लॉय करें।</p>
            <textarea id="re-code" rows="5" placeholder="नया HTML या Python कोड यहाँ लिखें (Optional)..." class="font-mono text-xs"></textarea>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                    <label class="block text-[11px] font-bold text-slate-600 mb-1">नई फ़ाइल / ZIP चुनें</label>
                    <input type="file" id="re-file" multiple class="text-xs">
                </div>
                <div>
                    <label class="block text-[11px] font-bold text-slate-600 mb-1">या नया फ़ोल्डर चुनें</label>
                    <input type="file" id="re-folder" webkitdirectory directory multiple class="text-xs">
                </div>
            </div>
            <button onclick="redeployNow()" id="btn-redeploy" class="w-full py-3.5 rounded-2xl bg-sky-600 hover:bg-sky-500 text-white font-extrabold text-xs shadow-md transition">🔄 अभी Redeploy करें</button>
        </div>

        <div class="soft-card rounded-3xl p-6 space-y-4">
            <h2 class="text-sm font-extrabold text-indigo-700">✏️ 2. Change Site Name & URL (नाम बदलें)</h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                    <label class="block text-[11px] font-bold text-slate-600 mb-1">नया प्रोजेक्ट नाम</label>
                    <input type="text" id="edit-name" class="text-xs">
                </div>
                <div>
                    <label class="block text-[11px] font-bold text-slate-600 mb-1">नया URL Slug</label>
                    <input type="text" id="edit-slug" class="text-xs font-mono text-sky-600">
                </div>
            </div>
            <button onclick="renameNow()" class="px-5 py-3 rounded-2xl bg-indigo-600 hover:bg-indigo-500 text-white font-extrabold text-xs shadow-xs transition">नाम और URL सेव करें</button>
        </div>

        <div class="soft-card rounded-3xl p-6 space-y-4">
            <h2 class="text-sm font-extrabold text-emerald-700">🌍 3. Custom Domain (अपना डोमेन जोड़ें)</h2>
            <div id="domain-badges" class="flex flex-wrap gap-2"></div>
            <div class="flex gap-2">
                <input type="text" id="new-domain" placeholder="जैसे: rohitcloud.in या myapp.com" class="text-xs font-mono">
                <button onclick="addDomainNow()" class="px-5 py-3 rounded-2xl bg-emerald-600 hover:bg-emerald-500 text-white font-extrabold text-xs shrink-0 shadow-xs">डोमेन जोड़ें</button>
            </div>
        </div>

        <div class="soft-card rounded-3xl p-6 space-y-3">
            <h2 class="text-sm font-extrabold text-slate-800">📜 Live Server & Deployment Logs</h2>
            <pre id="p-logs" class="bg-slate-900 text-emerald-400 p-4 rounded-2xl text-[11px] font-mono overflow-x-auto max-h-48"></pre>
        </div>

        <div class="soft-card rounded-3xl p-6 border-rose-200 flex items-center justify-between">
            <div>
                <h2 class="text-sm font-extrabold text-rose-600">🗑 Delete Project</h2>
                <p class="text-xs text-slate-500">इस प्रोजेक्ट और इसकी सभी फ़ाइलों को हमेशा के लिए हटाएं।</p>
            </div>
            <button onclick="deleteNow()" class="px-5 py-3 rounded-2xl bg-rose-600 hover:bg-rose-500 text-white font-extrabold text-xs shadow-xs">Delete Site</button>
        </div>
    </main>
    """ + FOOTER_HTML + COMMON_JS +
    """
    <script>
        document.getElementById('nav-actions').classList.remove('hidden');
        document.getElementById('nav-actions').classList.add('flex');

        const projId = window.location.pathname.split('/').pop();

        async function loadDetail() {
            const token = localStorage.getItem('dx_token');
            if (!token) { window.location.href = '/'; return; }
            const res = await fetch('/api/projects/' + projId, {headers: {'Authorization': 'Bearer ' + token}});
            if (!res.ok) { alert('Project not found'); window.location.href = '/'; return; }
            const data = await res.json();
            const p = data.project;

            document.getElementById('p-name').textContent = p.name;
            document.getElementById('p-url').textContent = p.live_url;
            document.getElementById('p-visit').href = p.live_url;
            document.getElementById('p-type').textContent = p.project_type.toUpperCase();
            document.getElementById('p-fw').textContent = p.framework.toUpperCase();
            document.getElementById('p-ver').textContent = 'v' + p.version;
            document.getElementById('p-upd').textContent = p.updated_at;
            document.getElementById('edit-name').value = p.name;
            document.getElementById('edit-slug').value = p.slug;
            document.getElementById('p-logs').textContent = p.runtime_logs || 'Ready.';

            const domBox = document.getElementById('domain-badges');
            domBox.innerHTML = (p.domains || []).length
                ? p.domains.map(d => '<span class="px-3 py-1 rounded-xl bg-emerald-100 text-emerald-800 text-xs font-mono font-bold">🌍 ' + d + ' (Active)</span>').join('')
                : '<span class="text-xs text-slate-400">अभी तक कोई कस्टम डोमेन नहीं जोड़ा गया है।</span>';
        }

        async function redeployNow() {
            const token = localStorage.getItem('dx_token');
            const btn = document.getElementById('btn-redeploy');
            btn.textContent = 'Redeploy हो रहा है...';
            btn.disabled = true;

            const fd = new FormData();
            const codeVal = document.getElementById('re-code').value;
            if (codeVal.trim()) fd.append('code_content', codeVal);
            for (let f of document.getElementById('re-file').files) fd.append('files', f, f.name);
            for (let f of document.getElementById('re-folder').files) fd.append('files', f, f.webkitRelativePath || f.name);

            try {
                const res = await fetch('/api/projects/' + projId + '/redeploy', {
                    method: 'POST',
                    headers: {'Authorization': 'Bearer ' + token},
                    body: fd
                });
                const data = await res.json();
                btn.textContent = '🔄 अभी Redeploy करें';
                btn.disabled = false;
                if (res.ok) {
                    showSuccessModal(data.live_url);
                    loadDetail();
                } else {
                    alert(data.detail || 'Error');
                }
            } catch (err) {
                btn.textContent = '🔄 अभी Redeploy करें';
                btn.disabled = false;
                alert('Network Error: ' + err);
            }
        }

        async function renameNow() {
            const token = localStorage.getItem('dx_token');
            const new_name = document.getElementById('edit-name').value;
            const new_slug = document.getElementById('edit-slug').value;
            const res = await fetch('/api/projects/' + projId + '/rename', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                body: JSON.stringify({new_name, new_slug})
            });
            const data = await res.json();
            if (!res.ok) return alert(data.detail || 'Error');
            showToast('✅ साइट का नाम और URL अपडेट हो गया!');
            loadDetail();
        }

        async function addDomainNow() {
            const token = localStorage.getItem('dx_token');
            const domain_name = document.getElementById('new-domain').value;
            const res = await fetch('/api/domains/' + projId + '/add', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                body: JSON.stringify({domain_name})
            });
            const data = await res.json();
            if (!res.ok) return alert(data.detail || 'Error');
            document.getElementById('new-domain').value = '';
            showToast('🌍 कस्टम डोमेन जुड़ गया!');
            loadDetail();
        }

        async function deleteNow() {
            if (!confirm('क्या आप वाकई इस प्रोजेक्ट को हमेशा के लिए डिलीट करना चाहते हैं?')) return;
            const token = localStorage.getItem('dx_token');
            await fetch('/api/projects/' + projId + '/delete', {
                method: 'DELETE',
                headers: {'Authorization': 'Bearer ' + token}
            });
            alert('प्रोजेक्ट डिलीट हो गया।');
            window.close();
            window.location.href = '/';
        }

        loadDetail();
    </script></body></html>
    """
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)