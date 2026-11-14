import os
import sys
import json
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
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="DeployX Cloud Platform", version="7.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
CUSTOM_ROOT_DOMAIN = os.environ.get("DEPLOYX_DOMAIN", "").strip().lower()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
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
        price_inr INTEGER DEFAULT 0,
        payment_id TEXT,
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()

init_db()

def get_public_base_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "127.0.0.1:8000"))
    return f"{proto}://{host}".rstrip("/")

def build_project_urls(request: Request, slug: str, project_type: str):
    path_url = f"/sites/{slug}/" if project_type == "frontend" else f"/app/{slug}/"
    if CUSTOM_ROOT_DOMAIN:
        live_url = f"https://{slug}.{CUSTOM_ROOT_DOMAIN}"
    else:
        live_url = f"{get_public_base_url(request)}{path_url}"
    return live_url, path_url

def hash_password(pwd: str) -> str:
    return hashlib.sha256(("deployx_salt_v7_" + pwd).encode("utf-8")).hexdigest()

def get_free_port(start_port: int = 9001) -> int:
    port = start_port
    while port < 9999:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
        port += 1
    return 9090

def sanitize_slug(raw_name: str) -> str:
    clean = "".join(ch if (ch.isalnum() or ch in "-_") else "-" for ch in raw_name.lower()).strip("-_")
    return clean or "my-site"

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
        first = files[0]
        wrapper = f"""<!DOCTYPE html><html><body style="background:#060913;color:#e2e8f0;font-family:sans-serif;padding:2rem;text-align:center;">
        <h2>Deployed File: {first}</h2>
        <p><a href="./{first}" style="color:#38bdf8;">Open File</a></p>
        </body></html>"""
        with open(os.path.join(site_dir, "index.html"), "w", encoding="utf-8") as f:
            f.write(wrapper)
        return first
    raise HTTPException(status_code=400, detail="कोई भी valid फ़ाइल नहीं मिली")

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
            info["proc"].wait(timeout=3)
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

@app.middleware("http")
async def universal_cloud_router(request: Request, call_next):
    host = request.headers.get("host", "").split(":")[0].lower()
    path = request.url.path

    if path.startswith("/app/"):
        parts = path.split("/", 3)
        slug = parts[2] if len(parts) > 2 else ""
        sub_path = "/" + parts[3] if len(parts) > 3 else "/"
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM projects WHERE slug = ?", (slug,))
        proj = c.fetchone()
        conn.close()
        if proj and proj["project_type"] == "backend" and proj["port"]:
            if proj["id"] not in RUNNING_PROCESSES:
                start_python_runtime(proj["id"], proj["slug"], proj["framework"], proj["port"], proj["entry_cmd"])
            return await proxy_to_backend(request, proj["port"], sub_path)

    if path.startswith("/api/") or path.startswith("/sites/"):
        return await call_next(request)

    proj = None
    if CUSTOM_ROOT_DOMAIN and host.endswith(f".{CUSTOM_ROOT_DOMAIN}") and host not in (CUSTOM_ROOT_DOMAIN, f"www.{CUSTOM_ROOT_DOMAIN}"):
        slug = host[: -(len(CUSTOM_ROOT_DOMAIN) + 1)]
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM projects WHERE slug = ?", (slug,))
        proj = c.fetchone()
        conn.close()
    elif host not in ("127.0.0.1", "localhost", "0.0.0.0", CUSTOM_ROOT_DOMAIN, ""):
        conn = get_db()
        c = conn.cursor()
        c.execute("""
            SELECT p.* FROM domains d
            JOIN projects p ON d.project_id = p.id
            WHERE d.domain_name = ? AND d.status = 'active'
        """, (host,))
        proj = c.fetchone()
        conn.close()

    if proj:
        if proj["project_type"] == "backend" and proj["port"]:
            if proj["id"] not in RUNNING_PROCESSES:
                start_python_runtime(proj["id"], proj["slug"], proj["framework"], proj["port"], proj["entry_cmd"])
            return await proxy_to_backend(request, proj["port"], path)
        else:
            site_dir = os.path.join(FRONTEND_DIR, proj["slug"])
            rel_path = path.lstrip("/") or "index.html"
            target_file = os.path.join(site_dir, rel_path)
            if os.path.isdir(target_file):
                target_file = os.path.join(target_file, "index.html")
            if os.path.exists(target_file) and os.path.isfile(target_file):
                return FileResponse(target_file)

    return await call_next(request)

def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Login required")
    token = authorization.split(" ")[1]
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, email, display_name, avatar_url, auth_provider FROM users WHERE token = ?", (token,))
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
    display_name: str

class FrontendCodePayload(BaseModel):
    project_name: str
    html_code: str

class RenameProjectPayload(BaseModel):
    new_name: str
    new_slug: str

class DomainPurchasePayload(BaseModel):
    domain_name: str
    price_inr: int
    payment_method: str

@app.get("/api/auth/me")
def verify_session(user=Depends(get_current_user)):
    return {"authenticated": True, "user": user}

@app.post("/api/auth/signup")
def signup(data: AuthPayload):
    email = data.email.strip().lower()
    if len(data.password) < 4:
        raise HTTPException(status_code=400, detail="कम से कम 4 अक्षरों का पासवर्ड डालें")
    token = secrets.token_hex(32)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    name = (data.display_name or email.split("@")[0]).strip()
    avatar = f"https://ui-avatars.com/api/?name={name}&background=06b6d4&color=fff"
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
def continue_with_google(data: GoogleAuthPayload):
    email = data.email.strip().lower()
    name = data.display_name.strip() or email.split("@")[0]
    avatar = f"https://ui-avatars.com/api/?name={name}&background=ea4335&color=fff"
    token = secrets.token_hex(32)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, email, display_name, avatar_url FROM users WHERE email = ?", (email,))
    existing = c.fetchone()
    if existing:
        c.execute("UPDATE users SET token = ? WHERE id = ?", (token, existing["id"]))
        conn.commit()
        user_data = dict(existing)
    else:
        c.execute(
            "INSERT INTO users (email, display_name, avatar_url, auth_provider, password_hash, token, created_at) VALUES (?, ?, ?, 'google', ?, ?, ?)",
            (email, name, avatar, hash_password(secrets.token_hex(16)), token, now),
        )
        conn.commit()
        user_data = {"email": email, "display_name": name, "avatar_url": avatar}
    conn.close()
    return {"token": token, "user": user_data}

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
        (proj_id, user["id"], live_url, f"Published live at {live_url}", now),
    )
    conn.commit()
    conn.close()
    return {"success": True, "project_id": proj_id, "live_url": live_url, "path_url": path_url}

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
            filename = os.path.basename(file.filename or "upload.html")
            dest = os.path.join(site_dir, filename)
            content = await file.read()
            with open(dest, "wb") as out:
                out.write(content)
            if filename.lower().endswith(".zip"):
                safe_extract_zip(dest, site_dir)
                os.remove(dest)

        entry = normalize_frontend_entry(site_dir)
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
        (proj_id, user["id"], live_url, f"Entry: {entry} | Live at {live_url}", now),
    )
    conn.commit()
    conn.close()
    return {"success": True, "project_id": proj_id, "live_url": live_url, "path_url": path_url}

@app.post("/api/deploy/frontend/{project_id}/update")
async def update_frontend_project(
    project_id: int,
    html_code: Optional[str] = Form(None),
    files: Optional[list[UploadFile]] = File(None),
    user=Depends(get_current_user),
):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE id = ? AND user_id = ? AND project_type = 'frontend'", (project_id, user["id"]))
    proj = c.fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404, detail="Project not found")

    site_dir = os.path.join(FRONTEND_DIR, proj["slug"])
    shutil.rmtree(site_dir, ignore_errors=True)
    os.makedirs(site_dir, exist_ok=True)

    if files:
        for file in files:
            fname = os.path.basename(file.filename or "index.html")
            dest = os.path.join(site_dir, fname)
            with open(dest, "wb") as out:
                out.write(await file.read())
            if fname.lower().endswith(".zip"):
                safe_extract_zip(dest, site_dir)
                os.remove(dest)
        normalize_frontend_entry(site_dir)
        log_msg = "Updated via file/ZIP upload."
    elif html_code is not None:
        with open(os.path.join(site_dir, "index.html"), "w", encoding="utf-8") as f:
            f.write(html_code)
        log_msg = "Updated via HTML editor."
    else:
        conn.close()
        raise HTTPException(status_code=400, detail="कोई अपडेट कंटेंट नहीं दिया गया")

    new_ver = proj["version"] + 1
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("UPDATE projects SET version = ?, updated_at = ? WHERE id = ?", (new_ver, now, project_id))
    c.execute(
        "INSERT INTO deployments (project_id, user_id, version, status, deployment_url, build_logs, created_at) VALUES (?, ?, ?, 'success', ?, ?, ?)",
        (project_id, user["id"], new_ver, proj["live_url"], log_msg, now),
    )
    conn.commit()
    conn.close()
    return {"success": True, "version": new_ver}

@app.post("/api/deploy/backend")
async def deploy_backend_project(
    request: Request,
    project_name: str = Form(...),
    framework: str = Form("auto"),
    custom_cmd: Optional[str] = Form(None),
    code_content: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    user=Depends(get_current_user),
):
    slug = make_unique_slug(project_name)
    proj_dir = os.path.join(BACKEND_DIR, slug)
    os.makedirs(proj_dir, exist_ok=True)

    detected_fw = framework
    try:
        if file and file.filename:
            fname = os.path.basename(file.filename)
            dest = os.path.join(proj_dir, fname)
            with open(dest, "wb") as out:
                out.write(await file.read())
            if fname.lower().endswith(".zip"):
                safe_extract_zip(dest, proj_dir)
                os.remove(dest)
            elif fname.lower().endswith(".py") and fname != "app.py":
                shutil.copy(dest, os.path.join(proj_dir, "app.py"))
        elif code_content and code_content.strip():
            with open(os.path.join(proj_dir, "app.py"), "w", encoding="utf-8") as f:
                f.write(code_content)
        else:
            raise HTTPException(status_code=400, detail="Python code या .py/.zip फ़ाइल दें")

        if detected_fw == "auto":
            combined = ""
            for fn in os.listdir(proj_dir):
                if fn.endswith(".py"):
                    with open(os.path.join(proj_dir, fn), "r", encoding="utf-8", errors="ignore") as f:
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
        return {"success": True, "project_id": proj_id, "live_url": live_url, "path_url": path_url}
    except Exception as e:
        shutil.rmtree(proj_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/deploy/backend/{project_id}/update")
async def update_backend_project(
    project_id: int,
    code_content: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    user=Depends(get_current_user),
):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE id = ? AND user_id = ? AND project_type = 'backend'", (project_id, user["id"]))
    proj = c.fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404, detail="Project not found")

    proj_dir = os.path.join(BACKEND_DIR, proj["slug"])
    stop_python_runtime(project_id)

    if file and file.filename:
        fname = os.path.basename(file.filename)
        dest = os.path.join(proj_dir, fname)
        with open(dest, "wb") as out:
            out.write(await file.read())
        if fname.lower().endswith(".zip"):
            safe_extract_zip(dest, proj_dir)
            os.remove(dest)
        elif fname.lower().endswith(".py"):
            shutil.copy(dest, os.path.join(proj_dir, "app.py"))
    elif code_content:
        with open(os.path.join(proj_dir, "app.py"), "w", encoding="utf-8") as f:
            f.write(code_content)

    boot_log = start_python_runtime(project_id, proj["slug"], proj["framework"], proj["port"], proj["entry_cmd"])
    new_ver = proj["version"] + 1
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("UPDATE projects SET version = ?, updated_at = ? WHERE id = ?", (new_ver, now, project_id))
    c.execute(
        "INSERT INTO deployments (project_id, user_id, version, status, deployment_url, build_logs, created_at) VALUES (?, ?, ?, 'success', ?, ?, ?)",
        (project_id, user["id"], new_ver, proj["live_url"], f"Redeployed v{new_ver}: {boot_log}", now),
    )
    conn.commit()
    conn.close()
    return {"success": True, "version": new_ver}

@app.post("/api/projects/{project_id}/rename")
def rename_project(request: Request, project_id: int, data: RenameProjectPayload, user=Depends(get_current_user)):
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
            raise HTTPException(status_code=400, detail=f"यह नाम '{new_slug}' पहले से किसी ने लिया हुआ है!")

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

    new_live_url, new_path_url = build_project_urls(request, new_slug, proj["project_type"])
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "UPDATE projects SET name = ?, slug = ?, live_url = ?, path_url = ?, updated_at = ? WHERE id = ?",
        (new_name, new_slug, new_live_url, new_path_url, now, project_id)
    )
    c.execute(
        "INSERT INTO deployments (project_id, user_id, version, status, deployment_url, build_logs, created_at) VALUES (?, ?, ?, 'success', ?, ?, ?)",
        (project_id, user["id"], proj["version"], new_live_url, f"URL updated to {new_live_url}", now),
    )
    conn.commit()
    conn.close()
    return {"success": True, "live_url": new_live_url}

@app.post("/api/projects/{project_id}/restart")
def restart_project(project_id: int, user=Depends(get_current_user)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE id = ? AND user_id = ?", (project_id, user["id"]))
    proj = c.fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404)

    if proj["project_type"] == "backend":
        boot_log = start_python_runtime(project_id, proj["slug"], proj["framework"], proj["port"], proj["entry_cmd"])
    else:
        boot_log = "Static site refreshed."

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
    c.execute(
        "INSERT INTO deployments (project_id, user_id, version, status, deployment_url, build_logs, created_at) VALUES (?, ?, ?, 'success', ?, ?, ?)",
        (project_id, user["id"], proj["version"], proj["live_url"], f"Restarted: {boot_log}", now),
    )
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/api/projects")
def get_all_projects(request: Request, user=Depends(get_current_user)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE user_id = ? ORDER BY updated_at DESC", (user["id"],))
    rows = [dict(r) for r in c.fetchall()]
    for r in rows:
        live_url, path_url = build_project_urls(request, r["slug"], r["project_type"])
        r["live_url"] = live_url
        r["path_url"] = path_url
        c.execute("SELECT domain_name, status FROM domains WHERE project_id = ?", (r["id"],))
        r["custom_domains"] = [dict(d) for d in c.fetchall()]
    conn.close()
    return {"projects": rows}

@app.get("/api/projects/{project_id}")
def get_project_details(request: Request, project_id: int, user=Depends(get_current_user)):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE id = ? AND user_id = ?", (project_id, user["id"]))
    proj = c.fetchone()
    if not proj:
        conn.close()
        raise HTTPException(status_code=404)
    proj_dict = dict(proj)
    live_url, path_url = build_project_urls(request, proj_dict["slug"], proj_dict["project_type"])
    proj_dict["live_url"] = live_url
    proj_dict["path_url"] = path_url

    c.execute("SELECT * FROM deployments WHERE project_id = ? ORDER BY id DESC", (project_id,))
    history = [dict(r) for r in c.fetchall()]

    c.execute("SELECT * FROM domains WHERE project_id = ?", (project_id,))
    domains = [dict(r) for r in c.fetchall()]
    conn.close()

    source_code = ""
    runtime_logs = ""
    if proj_dict["project_type"] == "frontend":
        idx = os.path.join(FRONTEND_DIR, proj_dict["slug"], "index.html")
        if os.path.exists(idx):
            with open(idx, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
    else:
        app_py = os.path.join(BACKEND_DIR, proj_dict["slug"], "app.py")
        if os.path.exists(app_py):
            with open(app_py, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
        log_f = os.path.join(LOGS_DIR, f"{proj_dict['slug']}.log")
        if os.path.exists(log_f):
            with open(log_f, "r", encoding="utf-8", errors="ignore") as f:
                runtime_logs = f.read()[-3500:]

    return {
        "project": proj_dict,
        "history": history,
        "domains": domains,
        "source_code": source_code,
        "runtime_logs": runtime_logs,
    }

@app.get("/api/domains/search")
def search_domain_availability(domain: str):
    d = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if "." not in d:
        d = f"{d}.com"
    ext = "." + d.split(".")[-1]
    prices = {".com": 899, ".in": 499, ".org": 799, ".net": 849, ".xyz": 149, ".io": 2499, ".co.in": 349}
    price = prices.get(ext, 699)

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM domains WHERE domain_name = ?", (d,))
    taken = c.fetchone() is not None
    conn.close()

    return {"domain": d, "available": not taken, "price_inr": price}

@app.post("/api/domains/{project_id}/buy")
def buy_and_connect_domain(project_id: int, data: DomainPurchasePayload, user=Depends(get_current_user)):
    d = data.domain_name.strip().lower()
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM projects WHERE id = ? AND user_id = ?", (project_id, user["id"]))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Project not found")

    pay_id = f"pay_DX_{secrets.token_hex(6).upper()}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        c.execute(
            """INSERT INTO domains (project_id, user_id, domain_name, price_inr, payment_id, status, created_at)
               VALUES (?, ?, ?, ?, ?, 'active', ?)""",
            (project_id, user["id"], d, data.price_inr, pay_id, now),
        )
        conn.commit()
        return {"success": True, "domain": d, "payment_id": pay_id, "status": "active"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="यह डोमेन पहले से रजिस्टर्ड है")
    finally:
        conn.close()

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

HTML_APP = """<!DOCTYPE html>
<html lang="hi" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DeployX — Free Static & Python Cloud Hosting</title>
    <style>
        .hidden { display: none !important; }
        body { background-color: #050811; color: #f1f5f9; font-family: system-ui, -apple-system, sans-serif; margin: 0; }
        input, textarea, select { background-color: #020617; color: #f1f5f9; border: 1px solid #1b263b; border-radius: 0.75rem; padding: 0.6rem 0.75rem; width: 100%; box-sizing: border-box; }
        button { cursor: pointer; }
    </style>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: { extend: { colors: { bgdark: '#050811', card: '#0c1322', borderc: '#1b263b' } } }
        }
    </script>
</head>
<body class="bg-bgdark text-slate-100 min-h-screen flex flex-col font-sans">
    <header class="sticky top-0 z-40 border-b border-borderc bg-card/90 backdrop-blur px-4 py-3 flex items-center justify-between">
        <div class="flex items-center space-x-2.5">
            <div class="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center font-black text-base shadow-lg shadow-cyan-500/25">DX</div>
            <div>
                <div class="font-extrabold text-lg leading-none bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">DeployX</div>
                <div class="text-[10px] text-slate-400 mt-0.5">24/7 Static & Backend Cloud</div>
            </div>
        </div>
        <div id="user-controls" class="hidden items-center space-x-2.5">
            <img id="nav-avatar" src="" class="w-7 h-7 rounded-full border border-cyan-500/40">
            <div class="hidden sm:block text-right">
                <div id="nav-name" class="text-xs font-bold text-slate-200 leading-none"></div>
                <div id="nav-email" class="text-[10px] text-slate-400"></div>
            </div>
            <button onclick="logout()" class="px-3 py-1.5 text-xs rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20 font-semibold">लॉग आउट</button>
        </div>
    </header>

    <div id="toast" class="hidden fixed bottom-5 right-5 z-50 bg-emerald-600 text-white text-xs font-bold px-4 py-2.5 rounded-xl shadow-xl"></div>
    <div id="boot-loader" class="flex-1 flex items-center justify-center p-8">
        <div class="text-center space-y-2">
            <div class="w-10 h-10 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
            <p class="text-xs text-slate-400">DeployX Cloud लोड हो रहा है...</p>
        </div>
    </div>

    <main id="main-wrap" class="hidden flex-1 max-w-5xl w-full mx-auto p-4 sm:p-6">
        <section id="auth-screen" class="max-w-md mx-auto mt-6 bg-card border border-borderc rounded-2xl p-6 shadow-2xl space-y-5">
            <div class="text-center space-y-1.5">
                <h1 class="text-xl font-extrabold">DeployX पर अपनी वेबसाइट लाइव करें</h1>
                <p class="text-xs text-slate-400">Static Website या Python Backend/API डिप्लॉय करें और तुरंत Live URL पाएं</p>
            </div>
            <button onclick="openGoogleModal()" class="w-full py-2.5 px-4 rounded-xl bg-white text-slate-900 font-bold text-sm flex items-center justify-center space-x-2.5 shadow hover:bg-slate-100 transition">
                <span>Continue with Google</span>
            </button>
            <div class="flex border-b border-borderc text-sm font-bold">
                <button onclick="setAuthTab('login')" id="tab-login" class="flex-1 pb-2 text-cyan-400 border-b-2 border-cyan-400">लॉग इन (Login)</button>
                <button onclick="setAuthTab('signup')" id="tab-signup" class="flex-1 pb-2 text-slate-400">नया अकाउंट (Sign Up)</button>
            </div>
            <form onsubmit="submitAuth(event)" class="space-y-3.5">
                <div id="name-wrap" class="hidden">
                    <label class="block text-xs text-slate-300 mb-1">आपका पूरा नाम</label>
                    <input type="text" id="auth-name" placeholder="Rohit Kumar">
                </div>
                <div>
                    <label class="block text-xs text-slate-300 mb-1">ईमेल एड्रेस</label>
                    <input type="email" id="auth-email" required placeholder="rohit@gmail.com">
                </div>
                <div>
                    <label class="block text-xs text-slate-300 mb-1">पासवर्ड</label>
                    <input type="password" id="auth-pass" required placeholder="••••••••">
                </div>
                <p id="auth-err" class="text-xs text-rose-400 hidden"></p>
                <button type="submit" id="auth-btn" class="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 font-bold text-sm shadow-lg">डैशबोर्ड में प्रवेश करें</button>
            </form>
        </section>

        <section id="dash-screen" class="hidden space-y-5">
            <div class="bg-gradient-to-r from-card to-slate-900 border border-borderc rounded-2xl p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                    <h1 class="text-lg font-extrabold">नमस्ते, <span id="dash-username" class="text-cyan-400">Developer</span> 👋</h1>
                    <p class="text-xs text-slate-400 mt-0.5">आपकी सभी लाइव वेबसाइट्स और APIs डेटाबेस में सुरक्षित हैं।</p>
                </div>
                <div class="flex space-x-3 text-center">
                    <div class="bg-slate-950 border border-borderc px-4 py-2 rounded-xl">
                        <div id="stat-total" class="text-lg font-extrabold text-cyan-400">0</div>
                        <div class="text-[10px] text-slate-400">कुल साइट्स</div>
                    </div>
                    <div class="bg-slate-950 border border-borderc px-4 py-2 rounded-xl">
                        <div id="stat-domains" class="text-lg font-extrabold text-emerald-400">0</div>
                        <div class="text-[10px] text-slate-400">कस्टम डोमेन</div>
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-3 gap-2 bg-card border border-borderc p-1.5 rounded-2xl">
                <button onclick="switchMainTab('projects')" id="m-tab-projects" class="py-2.5 px-2 rounded-xl text-xs sm:text-sm font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
                    मेरी साइट्स (<span id="tab-count">0</span>)
                </button>
                <button onclick="switchMainTab('frontend')" id="m-tab-frontend" class="py-2.5 px-2 rounded-xl text-xs sm:text-sm font-bold text-slate-400">
                    + Static Website
                </button>
                <button onclick="switchMainTab('backend')" id="m-tab-backend" class="py-2.5 px-2 rounded-xl text-xs sm:text-sm font-bold text-slate-400">
                    + Python Backend
                </button>
            </div>

            <div id="view-projects" class="space-y-4">
                <div id="projects-container" class="space-y-3"></div>
            </div>

            <div id="view-frontend" class="hidden bg-card border border-borderc rounded-2xl p-5 space-y-4">
                <div class="flex flex-wrap items-center justify-between gap-2">
                    <h2 class="text-base font-bold text-cyan-400">नई Static Website लाइव करें</h2>
                    <div class="flex space-x-1.5 text-xs">
                        <button onclick="setFeMode('code')" id="fe-m-code" class="px-3 py-1 rounded-lg bg-cyan-600 text-white font-semibold">HTML Code</button>
                        <button onclick="setFeMode('file')" id="fe-m-file" class="px-3 py-1 rounded-lg bg-slate-800 text-slate-300">File / ZIP Upload</button>
                    </div>
                </div>
                <div>
                    <label class="block text-xs text-slate-300 mb-1">साइट का नाम (URL स्लग बनेगा)</label>
                    <input type="text" id="fe-proj-name" placeholder="my-portfolio" class="text-sm font-mono text-cyan-400">
                </div>
                <div id="fe-code-panel" class="space-y-3">
                    <textarea id="fe-html-input" rows="7" class="font-mono text-xs">&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;head&gt;&lt;meta name="viewport" content="width=device-width, initial-scale=1.0"&gt;&lt;title&gt;My Live Website&lt;/title&gt;&lt;/head&gt;
&lt;body style="margin:0;background:#050811;color:#38bdf8;font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;text-align:center;"&gt;
  &lt;h1&gt;मेरी वेबसाइट लाइव है 🚀&lt;/h1&gt;
  &lt;p style="color:#94a3b8;"&gt;Hosted on DeployX Cloud&lt;/p&gt;
&lt;/body&gt;
&lt;/html&gt;</textarea>
                    <button onclick="deployFeCode()" id="btn-deploy-fe-code" class="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 font-bold text-sm">वेबसाइट लाइव करें</button>
                </div>
                <div id="fe-file-panel" class="hidden space-y-3">
                    <input type="file" id="fe-files-input" multiple class="text-xs">
                    <button onclick="deployFeFiles()" id="btn-deploy-fe-file" class="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 font-bold text-sm">फ़ाइलें अपलोड और लाइव करें</button>
                </div>
            </div>

            <div id="view-backend" class="hidden bg-card border border-borderc rounded-2xl p-5 space-y-4">
                <div class="flex flex-wrap items-center justify-between gap-2">
                    <h2 class="text-base font-bold text-emerald-400">Python Backend / API लाइव करें</h2>
                    <div class="flex space-x-1.5 text-xs">
                        <button onclick="setBeMode('code')" id="be-m-code" class="px-3 py-1 rounded-lg bg-emerald-600 text-white font-semibold">Python Code</button>
                        <button onclick="setBeMode('file')" id="be-m-file" class="px-3 py-1 rounded-lg bg-slate-800 text-slate-300">.PY / .ZIP Upload</button>
                    </div>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                        <label class="block text-xs text-slate-300 mb-1">प्रोजेक्ट का नाम</label>
                        <input type="text" id="be-proj-name" placeholder="my-api" class="text-sm font-mono text-emerald-400">
                    </div>
                    <div>
                        <label class="block text-xs text-slate-300 mb-1">Framework</label>
                        <select id="be-framework">
                            <option value="auto">Auto Detect (FastAPI / Flask)</option>
                            <option value="fastapi">FastAPI</option>
                            <option value="flask">Flask</option>
                        </select>
                    </div>
                </div>
                <div id="be-code-panel">
                    <textarea id="be-code-input" rows="7" class="font-mono text-xs">from fastapi import FastAPI
app = FastAPI()

@app.get("/")
def home():
    return {"status": "Live 24/7", "platform": "DeployX Cloud"}</textarea>
                </div>
                <div id="be-file-panel" class="hidden">
                    <input type="file" id="be-file-input" accept=".py,.zip" class="text-xs">
                </div>
                <button onclick="deployBackend()" id="btn-deploy-be" class="w-full py-3 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 font-bold text-sm">Python सर्वर लाइव करें</button>
            </div>
        </section>
    </main>

    <div id="google-modal" class="hidden fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
        <div class="bg-white text-slate-900 rounded-2xl max-w-sm w-full p-6 space-y-4">
            <div class="flex items-center justify-between">
                <span class="font-extrabold text-base text-blue-600">Sign in with Google</span>
                <button onclick="closeGoogleModal()" class="text-slate-400 text-sm font-bold">✕</button>
            </div>
            <form onsubmit="submitGoogleAuth(event)" class="space-y-3">
                <input type="text" id="g-name" required placeholder="आपका नाम" style="background:#fff;color:#000;border:1px solid #ccc;">
                <input type="email" id="g-email" required placeholder="aapka.email@gmail.com" style="background:#fff;color:#000;border:1px solid #ccc;">
                <button type="submit" class="w-full py-2.5 rounded-xl bg-blue-600 text-white font-bold text-sm">Continue with Google</button>
            </form>
        </div>
    </div>

    <div id="detail-modal" class="hidden fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-3 overflow-y-auto">
        <div class="bg-card border border-borderc rounded-2xl max-w-2xl w-full p-5 space-y-4 my-auto max-h-[90vh] overflow-y-auto">
            <div class="flex items-center justify-between border-b border-borderc pb-3">
                <div>
                    <h3 id="modal-title" class="text-base font-bold text-cyan-400">Site Settings</h3>
                    <p id="modal-sub" class="text-[11px] text-slate-400 font-mono"></p>
                </div>
                <button onclick="closeModal()" class="px-3 py-1 rounded-lg bg-slate-800 text-xs">✕ बंद करें</button>
            </div>

            <div class="bg-slate-950 border border-borderc rounded-xl p-3 space-y-2.5">
                <div class="text-[11px] text-slate-400">आपका असली Live URL (कहीं भी शेयर करें):</div>
                <div class="flex items-center gap-2">
                    <input type="text" id="modal-live-url-input" readonly class="text-xs font-mono text-cyan-400 bg-card">
                    <button onclick="copyUrl(document.getElementById('modal-live-url-input').value)" class="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-bold shrink-0">📋 Copy</button>
                </div>
                <div class="flex flex-wrap gap-2 pt-1">
                    <a id="modal-local-link" href="#" target="_blank" class="px-3.5 py-1.5 rounded-lg bg-cyan-600 text-white text-xs font-bold">Open Live Site ↗</a>
                    <button onclick="restartCurrentProject()" class="px-3 py-1.5 rounded-lg bg-amber-500/15 text-amber-400 border border-amber-500/30 text-xs font-semibold">↻ Restart</button>
                    <button onclick="deleteCurrentProject()" class="px-3 py-1.5 rounded-lg bg-rose-500/15 text-rose-400 border border-rose-500/30 text-xs font-semibold">🗑 Delete</button>
                </div>
            </div>

            <div class="bg-slate-950 border border-blue-500/30 rounded-xl p-4 space-y-2.5">
                <div class="text-xs font-extrabold text-blue-400">✏️ साइट का नाम और URL बदलें</div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <div>
                        <label class="text-[10px] text-slate-400">Project Name</label>
                        <input type="text" id="rename-title-input" class="text-xs">
                    </div>
                    <div>
                        <label class="text-[10px] text-slate-400">URL Slug</label>
                        <input type="text" id="rename-slug-input" class="text-xs font-mono text-cyan-400">
                    </div>
                </div>
                <button onclick="submitRenameProject()" class="px-4 py-2 rounded-lg bg-blue-600 text-white text-xs font-bold">नया नाम और URL सेव करें</button>
            </div>

            <div class="bg-slate-950 border border-cyan-500/30 rounded-xl p-4 space-y-3">
                <div class="text-xs font-extrabold text-cyan-400">🌍 कस्टम डोमेन खरीदें (.com, .in, .xyz)</div>
                <div id="modal-domain-list" class="space-y-1 text-xs"></div>
                <div class="flex gap-2">
                    <input type="text" id="domain-search-input" placeholder="apnanaam.in या myshop.com" class="flex-1 text-xs font-mono">
                    <button onclick="searchDomain()" class="px-3.5 py-2 rounded-lg bg-cyan-600 text-white text-xs font-bold">खोजें</button>
                </div>
                <div id="domain-result-box" class="hidden bg-card border border-borderc rounded-xl p-3 space-y-2.5"></div>
            </div>

            <div class="bg-slate-950 border border-borderc rounded-xl p-3.5 space-y-2">
                <div class="text-xs font-bold">🔄 कोड या फ़ाइल अपडेट करें</div>
                <textarea id="modal-code-editor" rows="5" class="font-mono text-xs"></textarea>
                <div class="flex flex-wrap items-center justify-between gap-2">
                    <input type="file" id="modal-file-upload" multiple class="text-[11px]">
                    <button onclick="submitProjectUpdate()" class="px-3.5 py-1.5 rounded-lg bg-cyan-600 text-white text-xs font-bold">Update Live Site</button>
                </div>
            </div>

            <div>
                <div class="text-xs font-bold mb-1">📜 Server & Build Logs</div>
                <pre id="modal-logs" class="bg-slate-950 border border-borderc rounded-xl p-3 text-[11px] font-mono text-emerald-400 overflow-x-auto max-h-32"></pre>
            </div>
        </div>
    </div>

    <script>
        let authMode = 'login';
        let beMode = 'code';
        let activeProject = null;

        function showToast(msg) {
            const t = document.getElementById('toast');
            t.innerText = msg;
            t.classList.remove('hidden');
            setTimeout(() => t.classList.add('hidden'), 2500);
        }

        function copyUrl(url) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(url).then(() => showToast('✅ URL कॉपी हो गया!'));
            } else {
                const inp = document.createElement('input');
                inp.value = url;
                document.body.appendChild(inp);
                inp.select();
                document.execCommand('copy');
                document.body.removeChild(inp);
                showToast('✅ URL कॉपी हो गया!');
            }
        }

        function setAuthTab(m) {
            authMode = m;
            document.getElementById('tab-login').className = m === 'login' ? 'flex-1 pb-2 text-cyan-400 border-b-2 border-cyan-400' : 'flex-1 pb-2 text-slate-400';
            document.getElementById('tab-signup').className = m === 'signup' ? 'flex-1 pb-2 text-cyan-400 border-b-2 border-cyan-400' : 'flex-1 pb-2 text-slate-400';
            document.getElementById('name-wrap').classList.toggle('hidden', m === 'login');
            document.getElementById('auth-btn').innerText = m === 'login' ? 'लॉग इन करें' : 'नया अकाउंट बनाएं';
        }

        async function submitAuth(e) {
            e.preventDefault();
            const email = document.getElementById('auth-email').value;
            const password = document.getElementById('auth-pass').value;
            const display_name = document.getElementById('auth-name').value;
            const errEl = document.getElementById('auth-err');
            errEl.classList.add('hidden');

            const url = authMode === 'login' ? '/api/auth/login' : '/api/auth/signup';
            const res = await fetch(url, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, password, display_name})
            });
            const data = await res.json();
            if (!res.ok) {
                errEl.innerText = data.detail || 'Error';
                errEl.classList.remove('hidden');
                return;
            }
            localStorage.setItem('deployx_token', data.token);
            showDashboard(data.user);
        }

        function openGoogleModal() { document.getElementById('google-modal').classList.remove('hidden'); }
        function closeGoogleModal() { document.getElementById('google-modal').classList.add('hidden'); }

        async function submitGoogleAuth(e) {
            e.preventDefault();
            const display_name = document.getElementById('g-name').value;
            const email = document.getElementById('g-email').value;
            const res = await fetch('/api/auth/google', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, display_name})
            });
            const data = await res.json();
            if (res.ok) {
                localStorage.setItem('deployx_token', data.token);
                closeGoogleModal();
                showDashboard(data.user);
            }
        }

        function logout() {
            const token = localStorage.getItem('deployx_token');
            if (token) fetch('/api/auth/logout', {method: 'POST', headers: {'Authorization': 'Bearer ' + token}});
            localStorage.removeItem('deployx_token');
            showAuth();
        }

        function switchMainTab(tab) {
            ['projects', 'frontend', 'backend'].forEach(t => {
                document.getElementById(`view-${t}`).classList.add('hidden');
                document.getElementById(`m-tab-${t}`).className = 'py-2.5 px-2 rounded-xl text-xs sm:text-sm font-bold text-slate-400';
            });
            document.getElementById(`view-${tab}`).classList.remove('hidden');
            document.getElementById(`m-tab-${tab}`).className = 'py-2.5 px-2 rounded-xl text-xs sm:text-sm font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30';
        }

        function setFeMode(m) {
            document.getElementById('fe-code-panel').classList.toggle('hidden', m !== 'code');
            document.getElementById('fe-file-panel').classList.toggle('hidden', m !== 'file');
        }

        function setBeMode(m) {
            beMode = m;
            document.getElementById('be-code-panel').classList.toggle('hidden', m !== 'code');
            document.getElementById('be-file-panel').classList.toggle('hidden', m !== 'file');
        }

        async function deployFeCode() {
            const btn = document.getElementById('btn-deploy-fe-code');
            btn.innerText = 'डिप्लॉय हो रहा है...';
            const token = localStorage.getItem('deployx_token');
            const project_name = document.getElementById('fe-proj-name').value || 'my-site';
            const html_code = document.getElementById('fe-html-input').value;
            const res = await fetch('/api/deploy/frontend/code', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                body: JSON.stringify({project_name, html_code})
            });
            btn.innerText = 'वेबसाइट लाइव करें';
            if (res.ok) {
                document.getElementById('fe-proj-name').value = '';
                showToast('🚀 वेबसाइट लाइव हो गई!');
                await loadProjects();
                switchMainTab('projects');
            }
        }

        async function deployFeFiles() {
            const token = localStorage.getItem('deployx_token');
            const files = document.getElementById('fe-files-input').files;
            if (!files.length) return alert('कृपया HTML या ZIP फ़ाइल चुनें');
            const btn = document.getElementById('btn-deploy-fe-file');
            btn.innerText = 'अपलोड हो रहा है...';
            const fd = new FormData();
            fd.append('project_name', document.getElementById('fe-proj-name').value || 'uploaded-site');
            for (let f of files) fd.append('files', f);
            const res = await fetch('/api/deploy/frontend', {
                method: 'POST', headers: {'Authorization': 'Bearer ' + token}, body: fd
            });
            btn.innerText = 'फ़ाइलें अपलोड और लाइव करें';
            if (res.ok) {
                showToast('🚀 वेबसाइट लाइव हो गई!');
                await loadProjects();
                switchMainTab('projects');
            }
        }

        async function deployBackend() {
            const token = localStorage.getItem('deployx_token');
            const btn = document.getElementById('btn-deploy-be');
            btn.innerText = 'सर्वर स्टार्ट हो रहा है...';
            const fd = new FormData();
            fd.append('project_name', document.getElementById('be-proj-name').value || 'python-api');
            fd.append('framework', document.getElementById('be-framework').value);
            if (beMode === 'code') {
                fd.append('code_content', document.getElementById('be-code-input').value);
            } else {
                const f = document.getElementById('be-file-input').files;
                if (!f.length) { btn.innerText = 'Python सर्वर लाइव करें'; return alert('कृपया .py या .zip फ़ाइल चुनें'); }
                fd.append('file', f[0]);
            }
            const res = await fetch('/api/deploy/backend', {
                method: 'POST', headers: {'Authorization': 'Bearer ' + token}, body: fd
            });
            btn.innerText = 'Python सर्वर लाइव करें';
            if (res.ok) {
                document.getElementById('be-proj-name').value = '';
                showToast('🚀 Python Backend लाइव हो गया!');
                await loadProjects();
                switchMainTab('projects');
            } else {
                const d = await res.json();
                alert(d.detail || 'Error');
            }
        }

        async function loadProjects() {
            const token = localStorage.getItem('deployx_token');
            const res = await fetch('/api/projects', {headers: {'Authorization': 'Bearer ' + token}});
            if (!res.ok) return showAuth();
            const data = await res.json();
            const projects = data.projects || [];

            let totalDomains = 0;
            projects.forEach(p => totalDomains += (p.custom_domains || []).length);

            document.getElementById('stat-total').innerText = projects.length;
            document.getElementById('tab-count').innerText = projects.length;
            document.getElementById('stat-domains').innerText = totalDomains;

            const box = document.getElementById('projects-container');
            if (!projects.length) {
                box.innerHTML = `<div class="bg-card border border-borderc rounded-2xl p-8 text-center space-y-2">
                    <p class="text-sm font-bold text-slate-300">अभी तक कोई वेबसाइट लाइव नहीं है</p>
                    <p class="text-xs text-slate-400">ऊपर "+ Static Website" या "+ Python Backend" पर क्लिक करके अपनी पहली साइट लाइव करें!</p>
                </div>`;
                return;
            }

            box.innerHTML = projects.map(p => {
                const domainBadges = (p.custom_domains || []).map(d =>
                    `<span class="inline-block text-[10px] px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-mono">🌐 https://${d.domain_name}</span>`
                ).join(' ');

                return `
                <div class="bg-card border border-borderc hover:border-cyan-500/40 transition rounded-2xl p-4 space-y-3">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div class="space-y-1">
                            <div class="flex items-center flex-wrap gap-2">
                                <span class="font-extrabold text-sm text-white">${p.name}</span>
                                <span class="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 font-bold">● LIVE</span>
                                <span class="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">${p.project_type.toUpperCase()} • v${p.version}</span>
                            </div>
                            <div class="flex flex-wrap gap-1 pt-0.5">${domainBadges}</div>
                        </div>
                        <div class="flex items-center space-x-2">
                            <a href="${p.live_url}" target="_blank" class="px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold">Open Site ↗</a>
                            <button onclick="openProjectModal(${p.id})" class="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-borderc text-xs font-bold">Update / Domain</button>
                        </div>
                    </div>
                    <div class="flex items-center justify-between bg-slate-950 border border-borderc rounded-xl px-3 py-2 gap-2">
                        <a href="${p.live_url}" target="_blank" class="text-xs font-mono text-cyan-400 truncate hover:underline">${p.live_url}</a>
                        <button onclick="copyUrl('${p.live_url}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-[11px] font-bold text-slate-200 shrink-0">📋 Copy URL</button>
                    </div>
                </div>`;
            }).join('');
        }

        async function openProjectModal(id) {
            const token = localStorage.getItem('deployx_token');
            const res = await fetch(`/api/projects/${id}`, {headers: {'Authorization': 'Bearer ' + token}});
            if (!res.ok) return;
            const data = await res.json();
            activeProject = data.project;

            document.getElementById('modal-title').innerText = activeProject.name;
            document.getElementById('modal-sub').innerText = `Type: ${activeProject.project_type} | Version: v${activeProject.version}`;
            document.getElementById('modal-live-url-input').value = activeProject.live_url;
            document.getElementById('modal-local-link').href = activeProject.live_url;
            document.getElementById('rename-title-input').value = activeProject.name;
            document.getElementById('rename-slug-input').value = activeProject.slug;
            document.getElementById('modal-code-editor').value = data.source_code || '';
            document.getElementById('domain-result-box').classList.add('hidden');

            document.getElementById('modal-domain-list').innerHTML = (data.domains || []).map(d =>
                `<div class="flex items-center justify-between bg-card px-2.5 py-1.5 rounded-lg border border-borderc">
                    <span class="font-mono text-emerald-400">https://${d.domain_name}</span>
                    <span class="text-[10px] text-slate-400">Active</span>
                </div>`
            ).join('') || '<div class="text-[11px] text-slate-400">अभी कोई कस्टम डोमेन नहीं जुड़ा है।</div>';

            const logs = (data.history || []).map(h => `[v${h.version}] ${h.build_logs}`).join('\n');
            document.getElementById('modal-logs').innerText = (data.runtime_logs ? data.runtime_logs + '\n' : '') + logs;

            document.getElementById('detail-modal').classList.remove('hidden');
        }

        function closeModal() {
            document.getElementById('detail-modal').classList.add('hidden');
            activeProject = null;
        }

        async function submitRenameProject() {
            if (!activeProject) return;
            const token = localStorage.getItem('deployx_token');
            const new_name = document.getElementById('rename-title-input').value;
            const new_slug = document.getElementById('rename-slug-input').value;
            const res = await fetch(`/api/projects/${activeProject.id}/rename`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                body: JSON.stringify({new_name, new_slug})
            });
            const d = await res.json();
            if (!res.ok) return alert(d.detail || 'Rename failed');
            showToast('✅ साइट का नाम और URL बदल गया!');
            await loadProjects();
            openProjectModal(activeProject.id);
        }

        async function searchDomain() {
            const q = document.getElementById('domain-search-input').value.trim();
            if (!q) return;
            const res = await fetch(`/api/domains/search?domain=${encodeURIComponent(q)}`);
            const data = await res.json();
            const box = document.getElementById('domain-result-box');
            box.classList.remove('hidden');

            if (!data.available) {
                box.innerHTML = `<div class="text-xs text-rose-400 font-bold">❌ ${data.domain} उपलब्ध नहीं है।</div>`;
                return;
            }
            box.innerHTML = `
                <div class="flex items-center justify-between">
                    <div>
                        <div class="text-sm font-extrabold text-white font-mono">${data.domain}</div>
                        <div class="text-[11px] text-emerald-400">✓ उपलब्ध है • Free SSL</div>
                    </div>
                    <div class="text-base font-black text-cyan-400">₹${data.price_inr}/yr</div>
                </div>
                <div class="grid grid-cols-2 gap-2 pt-1">
                    <button onclick="payAndBuyDomain('${data.domain}', ${data.price_inr}, 'UPI')" class="py-2 rounded-lg bg-emerald-600 text-white text-xs font-bold">Pay ₹${data.price_inr} UPI</button>
                    <button onclick="payAndBuyDomain('${data.domain}', ${data.price_inr}, 'Card')" class="py-2 rounded-lg bg-blue-600 text-white text-xs font-bold">Pay ₹${data.price_inr} Card</button>
                </div>
            `;
        }

        async function payAndBuyDomain(domain_name, price_inr, payment_method) {
            if (!activeProject) return;
            const token = localStorage.getItem('deployx_token');
            const res = await fetch(`/api/domains/${activeProject.id}/buy`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                body: JSON.stringify({domain_name, price_inr, payment_method})
            });
            const d = await res.json();
            if (!res.ok) return alert(d.detail || 'Payment failed');
            showToast(`🎉 डोमेन जुड़ गया: ${d.domain}`);
            await loadProjects();
            openProjectModal(activeProject.id);
        }

        async function submitProjectUpdate() {
            if (!activeProject) return;
            const token = localStorage.getItem('deployx_token');
            const fd = new FormData();
            const files = document.getElementById('modal-file-upload').files;
            const code = document.getElementById('modal-code-editor').value;

            if (activeProject.project_type === 'frontend') {
                if (files.length) for (let f of files) fd.append('files', f);
                else fd.append('html_code', code);
                await fetch(`/api/deploy/frontend/${activeProject.id}/update`, {
                    method: 'POST', headers: {'Authorization': 'Bearer ' + token}, body: fd
                });
            } else {
                if (files.length) fd.append('file', files[0]);
                else fd.append('code_content', code);
                await fetch(`/api/deploy/backend/${activeProject.id}/update`, {
                    method: 'POST', headers: {'Authorization': 'Bearer ' + token}, body: fd
                });
            }
            showToast('✅ लाइव साइट अपडेट हो गई!');
            await loadProjects();
            openProjectModal(activeProject.id);
        }

        async function restartCurrentProject() {
            if (!activeProject) return;
            const token = localStorage.getItem('deployx_token');
            await fetch(`/api/projects/${activeProject.id}/restart`, {
                method: 'POST', headers: {'Authorization': 'Bearer ' + token}
            });
            showToast('↻ रीस्टार्ट हो गया');
            openProjectModal(activeProject.id);
        }

        async function deleteCurrentProject() {
            if (!activeProject || !confirm('क्या आप इस प्रोजेक्ट को डिलीट करना चाहते हैं?')) return;
            const token = localStorage.getItem('deployx_token');
            await fetch(`/api/projects/${activeProject.id}/delete`, {
                method: 'DELETE', headers: {'Authorization': 'Bearer ' + token}
            });
            closeModal();
            showToast('🗑 प्रोजेक्ट डिलीट हो गया');
            loadProjects();
        }

        function showAuth() {
            document.getElementById('boot-loader').classList.add('hidden');
            document.getElementById('main-wrap').classList.remove('hidden');
            document.getElementById('auth-screen').classList.remove('hidden');
            document.getElementById('dash-screen').classList.add('hidden');
            document.getElementById('user-controls').classList.add('hidden');
        }

        function showDashboard(user) {
            document.getElementById('boot-loader').classList.add('hidden');
            document.getElementById('main-wrap').classList.remove('hidden');
            document.getElementById('auth-screen').classList.add('hidden');
            document.getElementById('dash-screen').classList.remove('hidden');
            document.getElementById('user-controls').classList.remove('hidden');
            document.getElementById('user-controls').classList.add('flex');

            document.getElementById('nav-name').innerText = user.display_name || 'Developer';
            document.getElementById('nav-email').innerText = user.email || '';
            document.getElementById('dash-username').innerText = user.display_name || 'Developer';
            if (user.avatar_url) document.getElementById('nav-avatar').src = user.avatar_url;

            loadProjects();
        }

        async function autoBoot() {
            const fallbackTimer = setTimeout(() => { showAuth(); }, 2000);
            try {
                const token = localStorage.getItem('deployx_token');
                if (!token) {
                    clearTimeout(fallbackTimer);
                    return showAuth();
                }
                const res = await fetch('/api/auth/me', {headers: {'Authorization': 'Bearer ' + token}});
                clearTimeout(fallbackTimer);
                if (!res.ok) {
                    localStorage.removeItem('deployx_token');
                    return showAuth();
                }
                const data = await res.json();
                showDashboard(data.user);
            } catch (e) {
                clearTimeout(fallbackTimer);
                    showAuth();
            }
        }

        autoBoot();
    </script>
</body>
</html>
