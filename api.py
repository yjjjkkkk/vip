"""
API Manager v2 — host Python APIs *and* Telegram bots from one dashboard.

Everything secret comes from environment variables (or a local .env file). See .env.example.
Run:   python api.py          (uses waitress automatically if installed)
"""
import os
import re
import io
import sys
import json
import time
import html
import socket
import signal
import hashlib
import secrets
import shutil
import zipfile
import tempfile
import threading
import subprocess
import collections
from urllib.parse import urlencode
from functools import wraps

import requests
from flask import (Flask, request, jsonify, render_template_string, redirect,
                   url_for, session, Response, send_file)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

try:
    import psutil
except ImportError:  # optional — only used for RAM / CPU numbers
    psutil = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BOOT_TIME = time.time()


# ======================================================================================
#  Config (.env + environment)
# ======================================================================================

def _load_dotenv(path):
    if not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except OSError:
        pass


_load_dotenv(os.path.join(BASE_DIR, ".env"))

# Where apps + their settings live. On Render the normal disk is wiped on every deploy —
# attach a Persistent Disk and point DATA_DIR at it (e.g. /var/data) to keep your apps.
DATA_DIR = os.environ.get("DATA_DIR") or BASE_DIR
APPS_DIR = os.path.join(DATA_DIR, "apps")
META_DIR = os.path.join(DATA_DIR, "meta")
os.makedirs(APPS_DIR, exist_ok=True)
os.makedirs(META_DIR, exist_ok=True)

ON_RENDER = bool(os.environ.get("RENDER"))

app = Flask(__name__)


def render_page(filename, **context):
    """Reads an .html file from the same folder as this script (no templates/ folder needed)."""
    with open(os.path.join(BASE_DIR, filename), encoding="utf-8") as f:
        return render_template_string(f.read(), **context)


def _load_or_create_secret_key():
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    path = os.path.join(DATA_DIR, ".secret_key")
    try:
        if os.path.exists(path):
            with open(path) as f:
                val = f.read().strip()
                if val:
                    return val
    except OSError:
        pass
    val = secrets.token_hex(32)
    try:
        with open(path, "w") as f:
            f.write(val)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return val


app.secret_key = _load_or_create_secret_key()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FORCE_HTTPS", "1" if ON_RENDER else "0") == "1"
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 12
app.config["MAX_CONTENT_LENGTH"] = 300 * 1024 * 1024

# FIX: behind Render's proxy request.remote_addr is the proxy's IP, so EVERY visitor shared one
# rate-limit bucket (one attacker could lock you out of your own dashboard). ProxyFix reads the
# real client IP from X-Forwarded-For. Set TRUSTED_PROXIES to however many proxies you have.
TRUSTED_PROXIES = int(os.environ.get("TRUSTED_PROXIES", "1" if ON_RENDER else "0"))
if TRUSTED_PROXIES:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXIES, x_proto=1, x_host=1)

LOG_LINES_KEPT = 3000
RESERVED_NAMES = {"", "login", "logout", "request-otp", "verify-otp", "api", "static",
                  "favicon.ico", "healthz", "robots.txt"}
# Never leak the manager's own secrets into hosted apps' environment (they can still be given
# per-app on the Env tab if you WANT a bot to have them).
SENSITIVE_ENV = {"ADMIN_PASSWORD", "SECRET_KEY", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "DATA_DIR"}
SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".venv", "venv", "__MACOSX"}

http_session = requests.Session()
_adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
http_session.mount("http://", _adapter)


# ======================================================================================
#  Telegram: alerts, OTP login, and the control bot
# ======================================================================================

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_ENABLED = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
# The control bot long-polls getUpdates. If a HOSTED bot uses the SAME token it will fight with
# it (HTTP 409). Use a different token for hosted bots, or set TELEGRAM_CONTROL=0.
TELEGRAM_CONTROL = TELEGRAM_ENABLED and os.environ.get("TELEGRAM_CONTROL", "1") != "0"


def tg_call(method, files=None, **params):
    if not TELEGRAM_BOT_TOKEN:
        return {"ok": False, "description": "telegram not configured"}
    try:
        r = requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}",
                          data=params, files=files, timeout=30 if files else 20)
        return r.json()
    except Exception as e:
        return {"ok": False, "description": str(e)}


def send_telegram(text, html_mode=False, markup=None, chat_id=None):
    """Best-effort — a Telegram outage must never break login or the dashboard."""
    if not TELEGRAM_ENABLED:
        return False
    params = {"chat_id": chat_id or TELEGRAM_CHAT_ID, "text": text[:4000],
              "disable_web_page_preview": "true"}
    if html_mode:
        params["parse_mode"] = "HTML"
    if markup:
        params["reply_markup"] = json.dumps(markup)
    return bool(tg_call("sendMessage", **params).get("ok"))


def send_telegram_async(text, html_mode=False):
    threading.Thread(target=send_telegram, args=(text, html_mode), daemon=True).start()


def send_otp_telegram(code, is_resend=False):
    label = "New API Manager login code" if is_resend else "API Manager login code"
    send_telegram(f"🔐 <b>{label}</b>\n\n<code>{code}</code>\n\nExpires in 5 minutes. Tap the code to copy it.",
                  html_mode=True)


def notify_security(text):
    send_telegram_async(f"🛡️ {text}")


# ======================================================================================
#  Client IP, rate limiting, CSRF, auth
# ======================================================================================

def client_ip():
    return request.remote_addr or "unknown"


class RateLimiter:
    def __init__(self, max_attempts, lockout_seconds):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self.state = {}
        self._lock = threading.Lock()

    def _prune(self, now):
        stale_after = max(3600, self.lockout_seconds * 4)
        for k in [k for k, v in self.state.items() if now - v["last_seen"] > stale_after]:
            del self.state[k]

    def locked_for(self, key):
        now = time.time()
        with self._lock:
            st = self.state.get(key)
            return max(0, st["locked_until"] - now) if st else 0

    def fail(self, key):
        now = time.time()
        with self._lock:
            if len(self.state) > 5000:
                self._prune(now)
            st = self.state.setdefault(key, {"fails": 0, "locked_until": 0.0, "last_seen": now})
            st["last_seen"] = now
            st["fails"] += 1
            if st["fails"] >= self.max_attempts:
                st["locked_until"] = now + self.lockout_seconds
                st["fails"] = 0
                return 0, True
            return self.max_attempts - st["fails"], False

    def reset(self, key):
        with self._lock:
            self.state.pop(key, None)


LOGIN_MAX_ATTEMPTS = 4
LOGIN_LOCKOUT_SECONDS = 15 * 60
login_limiter = RateLimiter(LOGIN_MAX_ATTEMPTS, LOGIN_LOCKOUT_SECONDS)
OTP_TTL_SECONDS = 5 * 60
otp_verify_limiter = RateLimiter(5, 15 * 60)
otp_request_limiter = RateLimiter(3, 10 * 60)
app_pass_limiter = RateLimiter(6, 10 * 60)
otp_state = {"code": None, "expires": 0, "attempts": 0}
auth_lock = threading.Lock()


def get_csrf_token():
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok


def csrf_ok():
    tok = session.get("csrf")
    supplied = request.form.get("csrf") or request.headers.get("X-CSRF-Token")
    return bool(tok) and bool(supplied) and secrets.compare_digest(tok, supplied)


ADMIN_PASSWORD_PLAIN = os.environ.get("ADMIN_PASSWORD", "")
if not ADMIN_PASSWORD_PLAIN:
    raise SystemExit(
        "\nADMIN_PASSWORD is not set.\n"
        "Set it as an environment variable (Render: Environment tab) or in a .env file.\n"
    )
if len(ADMIN_PASSWORD_PLAIN) < 8:
    print("\n*** WARNING: ADMIN_PASSWORD is shorter than 8 characters — pick something stronger. ***\n")
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD_PLAIN)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        if request.method in ("POST", "PUT", "DELETE", "PATCH") and not csrf_ok():
            return jsonify({"error": "security check failed — reload the page and try again"}), 403
        return view(*args, **kwargs)
    return wrapped


@app.route("/healthz")
def healthz():
    return "ok", 200, {"Content-Type": "text/plain"}


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = client_ip()
    error = None
    locked_remaining = login_limiter.locked_for(ip)
    if locked_remaining > 0:
        m, s = divmod(int(locked_remaining), 60)
        return render_page("login.html", error=f"Too many failed attempts. Try again in {m}m {s}s.",
                           locked=True, telegram_enabled=TELEGRAM_ENABLED, csrf_token=get_csrf_token())

    if request.method == "POST":
        if not csrf_ok():
            error = "Security check failed — reload the page and try again."
        else:
            pw = request.form.get("password", "")
            if check_password_hash(ADMIN_PASSWORD_HASH, pw):
                login_limiter.reset(ip)
                session.permanent = True
                session["admin"] = True
                session.pop("csrf", None)
                return redirect(url_for("index"))
            remaining, locked_now = login_limiter.fail(ip)
            if locked_now:
                error = "Too many failed attempts. Locked for 15 minutes."
                notify_security(f"Admin login locked out after repeated failures from {ip}.")
            else:
                error = f"Incorrect password. {remaining} attempt(s) left."
    return render_page("login.html", error=error, telegram_enabled=TELEGRAM_ENABLED, csrf_token=get_csrf_token())


@app.route("/request-otp", methods=["POST"])
def request_otp():
    if not TELEGRAM_ENABLED or not csrf_ok():
        return redirect(url_for("login"))
    ip = client_ip()
    if login_limiter.locked_for(ip) > 0:
        return redirect(url_for("login"))
    remaining_lock = otp_request_limiter.locked_for(ip)
    if remaining_lock > 0:
        session["awaiting_otp"] = True
        m, s = divmod(int(remaining_lock), 60)
        return render_page("verify_otp.html", error=f"Too many codes requested. Try again in {m}m {s}s.",
                           locked=True, csrf_token=get_csrf_token())
    otp_request_limiter.fail(ip)
    code = f"{secrets.randbelow(1000000):06d}"
    with auth_lock:
        otp_state.update({"code": code, "expires": time.time() + OTP_TTL_SECONDS, "attempts": 0})
    otp_verify_limiter.reset(ip)
    send_otp_telegram(code)
    session["awaiting_otp"] = True
    return redirect(url_for("verify_otp"))


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if not session.get("awaiting_otp"):
        return redirect(url_for("login"))
    ip = client_ip()
    error = None
    now = time.time()

    remaining_lock = otp_verify_limiter.locked_for(ip)
    if remaining_lock > 0:
        m, s = divmod(int(remaining_lock), 60)
        return render_page("verify_otp.html", error=f"Too many attempts. Try again in {m}m {s}s.",
                           locked=True, csrf_token=get_csrf_token())

    if request.method == "POST":
        if not csrf_ok():
            error = "Security check failed — reload the page and try again."
        elif request.form.get("resend"):
            resend_lock = otp_request_limiter.locked_for(ip)
            if resend_lock > 0:
                m, s = divmod(int(resend_lock), 60)
                error = f"Too many codes requested. Try again in {m}m {s}s."
            else:
                otp_request_limiter.fail(ip)
                code = f"{secrets.randbelow(1000000):06d}"
                with auth_lock:
                    otp_state.update({"code": code, "expires": now + OTP_TTL_SECONDS, "attempts": 0})
                send_otp_telegram(code, is_resend=True)
                error = "A new code was sent."
        else:
            entered = request.form.get("otp", "").strip()
            with auth_lock:
                expired = now > otp_state["expires"]
                valid_code = otp_state["code"]
            correct = bool(entered) and not expired and valid_code and secrets.compare_digest(entered, valid_code)
            if correct:
                otp_verify_limiter.reset(ip)
                session.permanent = True
                session["admin"] = True
                session.pop("awaiting_otp", None)
                session.pop("csrf", None)
                with auth_lock:
                    otp_state.update({"code": None, "attempts": 0})
                return redirect(url_for("index"))
            if expired:
                error = "Code expired — request a new one."
            else:
                remaining, locked_now = otp_verify_limiter.fail(ip)
                if locked_now:
                    error = "Too many attempts — locked for 15 minutes."
                    notify_security(f"OTP verification locked out after repeated failures from {ip}.")
                else:
                    error = f"Incorrect code. {remaining} attempt(s) left."
    return render_page("verify_otp.html", error=error, csrf_token=get_csrf_token())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


# ======================================================================================
#  App registry
# ======================================================================================

registry = {}
# FIX: was a plain Lock — notify_crash() re-acquired it while _boot_sequence already held it,
# which deadlocked the whole dashboard whenever an app failed to launch.
lock = threading.RLock()


class LogBuf:
    """Ring buffer of numbered lines so the UI can ask only for what's new ("since")."""

    def __init__(self, maxlen=LOG_LINES_KEPT):
        self.d = collections.deque(maxlen=maxlen)
        self.seq = 0
        self.epoch = 0
        self._l = threading.Lock()

    def add(self, text):
        with self._l:
            for ln in (str(text).splitlines() or [""]):
                self.seq += 1
                self.d.append((self.seq, ln))

    def read(self, since=0, epoch=-1):
        with self._l:
            reset = epoch != self.epoch
            if reset:
                since = 0
            return [l for s, l in self.d if s > since], self.seq, self.epoch, reset

    def tail(self, n):
        with self._l:
            return [l for _, l in list(self.d)[-n:]]

    def clear(self):
        with self._l:
            self.d.clear()
            self.epoch += 1


def dlog(info, msg):
    info["logs"].add(f"[manager {time.strftime('%H:%M:%S')}] {msg}")


def app_dir_of(name):
    return os.path.join(APPS_DIR, name)


def meta_path(name):
    return os.path.join(META_DIR, f"{name}.json")


def new_entry(name, d, entry, meta=None):
    meta = meta or {}
    return {
        "name": name, "dir": d, "entry": entry, "port": None, "process": None,
        "status": "stopped", "uploaded_at": time.time(), "started_at": None,
        "logs": LogBuf(),
        "protected": bool(meta.get("protected")), "password_hash": meta.get("password_hash"),
        "env": dict(meta.get("env") or {}),
        "desired": bool(meta.get("desired")),            # should this be running? (restored on boot)
        "auto_restart": meta.get("auto_restart", True),   # restart automatically when it crashes
        "gen": 0, "restart_times": [], "exit_code": None, "installed_hash": None,
        "total_requests": 0, "success_count": 0, "error_count": 0, "total_latency_ms": 0.0,
        "request_times": collections.deque(maxlen=300), "last_request_at": None,
        "_fs": None, "_ps": None,
    }


def save_meta(info):
    data = {k: info.get(k) for k in ("entry", "protected", "password_hash", "env", "desired", "auto_restart")}
    path = meta_path(info["name"])
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        pass


def py_files_in(d):
    out = []
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            if f.endswith(".py"):
                out.append(os.path.relpath(os.path.join(root, f), d).replace("\\", "/"))
    return out


def pick_entry(py_files):
    top = [f for f in py_files if "/" not in f]
    for pref in ("main.py", "app.py", "bot.py", "run.py", "index.py"):
        if pref in top:
            return pref
    return sorted(top)[0] if top else sorted(py_files)[0]


def load_existing_apps():
    for name in sorted(os.listdir(APPS_DIR)):
        if name.lower() in RESERVED_NAMES:
            continue
        d = app_dir_of(name)
        if not os.path.isdir(d):
            continue
        py = py_files_in(d)
        if not py:
            continue
        meta = {}
        try:
            with open(meta_path(name), encoding="utf-8") as f:
                meta = json.load(f)
        except (OSError, ValueError):
            pass
        entry = meta.get("entry")
        if not entry or not os.path.isfile(os.path.join(d, entry)):
            entry = pick_entry(py)
        info = new_entry(name, d, entry, meta)
        info["uploaded_at"] = os.path.getmtime(d)
        registry[name] = info


load_existing_apps()


def safe_join(base, rel):
    """Resolve rel inside base. Returns (full_path, normalised_rel) or None if it escapes."""
    rel = (rel or "").replace("\\", "/").lstrip("/")
    if not rel:
        return None
    norm = os.path.normpath(rel).replace("\\", "/")
    if norm.startswith("..") or os.path.isabs(norm) or norm == ".":
        return None
    root = os.path.realpath(base)
    full = os.path.realpath(os.path.join(root, norm))
    if not full.startswith(root + os.sep):
        return None
    return full, norm


def fmt_uptime(sec):
    sec = int(sec)
    h, m, s = sec // 3600, (sec % 3600) // 60, sec % 60
    return f"{h}h {m}m" if h else (f"{m}m {s}s" if m else f"{s}s")


# ---------- file scan (cached — the dashboard polls every couple of seconds) ----------

BOT_RE = re.compile(r"telegram|telebot|aiogram|pyrogram|telethon|discord|slack_bolt|slack_sdk", re.I)
WEB_RE = re.compile(r"flask|fastapi|uvicorn|http\.server|aiohttp|sanic|bottle|django|tornado|waitress|gunicorn|hypercorn", re.I)


def scan_app(info):
    d = info["dir"]
    files, total = [], 0
    for root, dirs, fnames in os.walk(d):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for fname in fnames:
            full = os.path.join(root, fname)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            total += size
            files.append({"name": os.path.relpath(full, d).replace("\\", "/"), "size": size,
                          "is_py": fname.endswith(".py")})
    files.sort(key=lambda x: x["name"])

    blob = ""
    for f in files:
        if f["is_py"] and f["size"] < 200_000 and len(blob) < 600_000:
            try:
                with open(os.path.join(d, f["name"]), encoding="utf-8", errors="ignore") as fh:
                    blob += fh.read() + "\n"
            except OSError:
                pass
    try:
        with open(os.path.join(d, "requirements.txt"), encoding="utf-8", errors="ignore") as fh:
            blob += fh.read()
    except OSError:
        pass
    bot, web = bool(BOT_RE.search(blob)), bool(WEB_RE.search(blob))
    kind = "bot+web" if bot and web else "bot" if bot else "web" if web else "script"
    return {"t": time.time(), "files": files, "size": total, "kind": kind}


def fs_info(info, force=False):
    c = info.get("_fs")
    if c and not force and time.time() - c["t"] < 8:
        return c
    c = scan_app(info)
    info["_fs"] = c
    return c


def proc_stats(info):
    if not psutil:
        return {"mem": None, "cpu": None}
    proc = info.get("process")
    if not proc or proc.poll() is not None:
        info["_ps"] = None
        return {"mem": 0, "cpu": 0.0}
    try:
        ps = info.get("_ps")
        if ps is None or ps.pid != proc.pid:
            ps = psutil.Process(proc.pid)
            info["_ps"] = ps
        mem = ps.memory_info().rss
        for ch in ps.children(recursive=True):
            try:
                mem += ch.memory_info().rss
            except Exception:
                pass
        return {"mem": mem, "cpu": round(ps.cpu_percent(None), 1)}
    except Exception:
        return {"mem": None, "cpu": None}


def system_stats():
    out = {"mem_used": None, "mem_total": None, "cpu": None, "uptime": time.time() - BOOT_TIME}
    # Inside a container (Render) the cgroup limit is the real ceiling, not the host's RAM.
    try:
        for cur, mx in (("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.max"),
                        ("/sys/fs/cgroup/memory/memory.usage_in_bytes", "/sys/fs/cgroup/memory/memory.limit_in_bytes")):
            if os.path.exists(cur) and os.path.exists(mx):
                used = int(open(cur).read().strip())
                lim = open(mx).read().strip()
                if lim.isdigit() and int(lim) < 1 << 50:
                    out["mem_used"], out["mem_total"] = used, int(lim)
                break
    except Exception:
        pass
    if psutil:
        try:
            if out["mem_total"] is None:
                vm = psutil.virtual_memory()
                out["mem_used"], out["mem_total"] = vm.total - vm.available, vm.total
            out["cpu"] = psutil.cpu_percent(None)
        except Exception:
            pass
    return out


def compute_rps(info, window=60):
    now = time.time()
    return round(len([t for t in list(info["request_times"]) if t >= now - window]) / window, 2)


# ======================================================================================
#  Process lifecycle
# ======================================================================================

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def kill_proc(proc):
    if not proc or proc.poll() is not None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            if hasattr(os, "killpg"):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except Exception:
            pass


def _pump_logs(name, proc):
    try:
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            info = registry.get(name)
            if info is None:
                break
            info["logs"].add(line)
    except Exception:
        pass


def run_pip(info, cwd):
    """pip install -r requirements.txt, streaming every line into the app's log."""
    in_venv = sys.prefix != sys.base_prefix
    base = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "-r", "requirements.txt"]
    attempts = [base] if in_venv else [base + ["--break-system-packages"], base]
    rc, out = 1, ""
    for cmd in attempts:
        p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out = ""
        t0 = time.time()
        for ln in p.stdout:
            out += ln
            info["logs"].add(ln.rstrip("\n"))
            if time.time() - t0 > 900:
                p.kill()
                break
        rc = p.wait()
        if rc == 0 or "no such option" not in out.lower():
            break
    return rc


def _boot_sequence(name, gen):
    def current():
        i = registry.get(name)
        return i if i and i["gen"] == gen else None

    with lock:
        info = current()
        if not info:
            return
        target_dir, entry = info["dir"], info["entry"]
        info["exit_code"] = None
        req_path = os.path.join(target_dir, "requirements.txt")
        req_hash = None
        if os.path.exists(req_path):
            with open(req_path, "rb") as f:
                req_hash = hashlib.sha1(f.read()).hexdigest()
        need_install = bool(req_hash) and req_hash != info["installed_hash"]
        info["status"] = "installing" if need_install else "starting"
        info["logs"].add("──────────────── start ────────────────")

    if need_install:
        dlog(info, "installing requirements.txt …")
        try:
            rc = run_pip(info, target_dir)
        except Exception as e:
            rc = 1
            dlog(info, f"installer error: {e}")
        with lock:
            info = current()
            if not info:
                return
            if rc != 0:
                dlog(info, "install failed — see output above")
                info["status"] = "crashed"
                info["desired"] = False
                save_meta(info)
                fail = True
            else:
                info["installed_hash"] = req_hash
                dlog(info, "dependencies installed")
                info["status"] = "starting"
                fail = False
        if fail:
            send_telegram_async(f"🚨 {name}: dependency install failed. Check the logs.")
            return

    port = find_free_port()
    env = {k: v for k, v in os.environ.items() if k not in SENSITIVE_ENV}
    with lock:
        info = current()
        if not info:
            return
        env.update(info["env"])
    env.update({"PORT": str(port), "HOST": "127.0.0.1", "PYTHONUNBUFFERED": "1"})

    with lock:
        info = current()
        if not info:
            return
        dlog(info, f"starting {entry} (port {port}) …")
        try:
            proc = subprocess.Popen(
                [sys.executable, "-u", entry], env=env, cwd=target_dir,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception as e:
            dlog(info, f"failed to launch: {e}")
            info["status"] = "crashed"
            send_telegram_async(f"🚨 {name}: failed to launch — {e}")
            return
        info["process"], info["port"], info["started_at"] = proc, port, time.time()

    threading.Thread(target=_pump_logs, args=(name, proc), daemon=True).start()

    time.sleep(1.5)
    with lock:
        info = current()
        if not info or info["process"] is not proc:
            return
        alive = proc.poll() is None
        if alive:
            info["status"] = "running"
            dlog(info, "running")
        else:
            info["status"] = "crashed"
            info["exit_code"] = proc.returncode
            dlog(info, f"exited immediately (code {proc.returncode}) — check the output above")
    if alive:
        threading.Thread(target=_watch_running, args=(name, proc, gen), daemon=True).start()
    else:
        _handle_exit(name, proc, gen)


def _watch_running(name, proc, gen):
    proc.wait()
    time.sleep(0.3)  # let the log pump drain the last lines
    _handle_exit(name, proc, gen)


def _handle_exit(name, proc, gen):
    """Process died on its own. Maybe schedule an automatic restart (max 5 per 10 min)."""
    with lock:
        info = registry.get(name)
        if not info or info["process"] is not proc or info["gen"] != gen:
            return  # stopped/restarted by the user meanwhile
        info["status"] = "crashed"
        info["exit_code"] = proc.returncode
        dlog(info, f"process exited (code {proc.returncode})")
        now = time.time()
        info["restart_times"] = [t for t in info["restart_times"] if now - t < 600]
        tail = "\n".join(info["logs"].tail(6))
        if info["desired"] and info["auto_restart"] and len(info["restart_times"]) < 5:
            info["restart_times"].append(now)
            n = len(info["restart_times"])
            delay = min(3 * n, 30)
            dlog(info, f"auto-restart {n}/5 in {delay}s …")
            threading.Timer(delay, _auto_restart, (name, info["gen"])).start()
            msg = f"🚨 {name} crashed (code {proc.returncode}) — restarting in {delay}s ({n}/5)"
        elif info["desired"] and info["auto_restart"]:
            dlog(info, "crash loop — giving up. Press Start when you've fixed it.")
            info["desired"] = False
            save_meta(info)
            msg = f"🛑 {name} is crash-looping — auto-restart stopped."
        else:
            msg = f"🚨 {name} crashed (code {proc.returncode})."
    send_telegram_async(f"{msg}\n\n{tail}"[:3800])


def _auto_restart(name, gen):
    with lock:
        info = registry.get(name)
        if not info or info["gen"] != gen or info["status"] != "crashed":
            return
    start_app(name)


def start_app(name):
    with lock:
        info = registry.get(name)
        if not info:
            return False, "not found"
        if info["status"] in ("running", "starting", "installing"):
            return False, "already running"
        info["gen"] += 1
        gen = info["gen"]
        info["status"] = "starting"
        info["desired"] = True
        save_meta(info)
    threading.Thread(target=_boot_sequence, args=(name, gen), daemon=True).start()
    return True, "starting"


def stop_app(name, manual=True):
    with lock:
        info = registry.get(name)
        if not info:
            return False, "not found"
        info["gen"] += 1
        proc = info["process"]
        info.update(process=None, port=None, status="stopped", started_at=None, _ps=None)
        if manual:
            info["desired"] = False
            info["restart_times"] = []
            save_meta(info)
    kill_proc(proc)  # outside the lock — can take a few seconds
    with lock:
        if name in registry:
            dlog(registry[name], "stopped")
    return True, "stopped"


def restart_app(name):
    if name not in registry:
        return False, "not found"
    stop_app(name, manual=False)
    return start_app(name)


def delete_app(name):
    with lock:
        info = registry.get(name)
        if not info:
            return False
        info["gen"] += 1
        proc, d = info["process"], info["dir"]
        del registry[name]
    kill_proc(proc)
    shutil.rmtree(d, ignore_errors=True)
    try:
        os.remove(meta_path(name))
    except OSError:
        pass
    return True


# ======================================================================================
#  Deploying code (shared by the web UI and the Telegram bot)
# ======================================================================================

def safe_name_from(filename):
    raw = os.path.splitext(os.path.basename(filename))[0]
    cleaned = "".join(c for c in raw if c.isalnum() or c in "-_")[:40] or f"app{int(time.time())}"
    return f"{cleaned}-app" if cleaned.lower() in RESERVED_NAMES else cleaned


def unique_name(safe):
    name, i = safe, 1
    while name in registry or name.lower() in RESERVED_NAMES or os.path.exists(app_dir_of(name)):
        name = f"{safe}_{i}"
        i += 1
    return name


def deploy_py(filename, data, target=None):
    """Create a new app from one .py file, or overwrite files of `target`. -> dict"""
    fname = secure_filename(os.path.basename(filename)) or "main.py"
    if not fname.endswith(".py"):
        fname += ".py"
    with lock:
        existing = bool(target and target in registry)
        if existing:
            name = target
            d = registry[name]["dir"]
        else:
            name = unique_name(safe_name_from(filename))
            d = app_dir_of(name)
            os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, fname), "wb") as f:
        f.write(data)
    with lock:
        if existing:
            info = registry[name]
            info["_fs"] = None
            if not os.path.isfile(os.path.join(d, info["entry"])):
                info["entry"] = fname
        else:
            registry[name] = new_entry(name, d, fname)
            save_meta(registry[name])
    return {"name": name, "entry": fname, "existing": existing}


def extract_zip_to(zpath, dest):
    count = 0
    with zipfile.ZipFile(zpath) as zf:
        if sum(i.file_size for i in zf.infolist()) > 600 * 1024 * 1024:
            raise ValueError("zip is too large when extracted (limit 600 MB)")
        for m in zf.infolist():
            if m.is_dir() or (m.external_attr >> 16) & 0o170000 == 0o120000:  # skip dirs + symlinks
                continue
            sj = safe_join(dest, m.filename)
            if not sj:
                continue  # zip-slip guard
            os.makedirs(os.path.dirname(sj[0]), exist_ok=True)
            with zf.open(m) as src, open(sj[0], "wb") as out:
                shutil.copyfileobj(src, out)
            count += 1
    return count


def deploy_zip(filename, zip_path, target=None):
    tmp = tempfile.mkdtemp()
    try:
        try:
            extract_zip_to(zip_path, tmp)
        except zipfile.BadZipFile:
            raise ValueError("invalid zip file")
        entries = [e for e in os.listdir(tmp) if e not in SKIP_DIRS]
        root = tmp
        if len(entries) == 1 and os.path.isdir(os.path.join(tmp, entries[0])):
            root = os.path.join(tmp, entries[0])
        py = py_files_in(root)
        if not py:
            raise ValueError("zip contains no .py files")
        with lock:
            existing = bool(target and target in registry)
            if existing:
                name, d = target, registry[target]["dir"]
            else:
                name = unique_name(safe_name_from(filename))
                d = app_dir_of(name)
        os.makedirs(d, exist_ok=True)
        shutil.copytree(root, d, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(*SKIP_DIRS))
        entry = pick_entry(py)
        with lock:
            if existing:
                info = registry[name]
                info["_fs"] = None
                info["installed_hash"] = None
                if not os.path.isfile(os.path.join(d, info["entry"])):
                    info["entry"] = entry
                entry = info["entry"]
            else:
                registry[name] = new_entry(name, d, entry)
                save_meta(registry[name])
        return {"name": name, "entry": entry, "files": len(py), "existing": existing}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def zip_app_bytes(name):
    with lock:
        info = registry.get(name)
        if not info:
            return None
        d = info["dir"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            for f in files:
                full = os.path.join(root, f)
                zf.write(full, os.path.relpath(full, d))
    buf.seek(0)
    return buf


def parse_env_text(text):
    env = {}
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise ValueError(f"line {n}: expected KEY=VALUE")
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", k):
            raise ValueError(f"line {n}: '{k}' is not a valid variable name")
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        env[k] = v
    return env


# ======================================================================================
#  Dashboard + API
# ======================================================================================

@app.route("/")
@login_required
def index():
    return render_page("index.html", telegram_enabled=TELEGRAM_ENABLED, csrf_token=get_csrf_token())


@app.route("/api/me")
@login_required
def api_me():
    return jsonify({"csrf": get_csrf_token(), "telegram": TELEGRAM_ENABLED, "control": TELEGRAM_CONTROL})


def app_summary(info, now):
    fs = fs_info(info)
    st = info["status"]
    total_req = info["total_requests"]
    ps = proc_stats(info) if st in ("running", "starting") else {"mem": 0, "cpu": 0.0}
    web = fs["kind"] != "bot"
    return {
        "name": info["name"], "status": st, "kind": fs["kind"], "entry": info["entry"],
        "url": f"/{info['name']}/" if web and st in ("running", "starting") else None,
        "uploaded_at": info["uploaded_at"],
        "uptime": (now - info["started_at"]) if info["started_at"] and st == "running" else None,
        "files": fs["files"], "storage_bytes": fs["size"],
        "has_requirements": any(f["name"] == "requirements.txt" for f in fs["files"]),
        "protected": info["protected"], "auto_restart": info["auto_restart"], "desired": info["desired"],
        "exit_code": info["exit_code"], "restarts": len(info["restart_times"]),
        "total_requests": total_req, "success_count": info["success_count"], "error_count": info["error_count"],
        "rps": compute_rps(info),
        "avg_latency_ms": round(info["total_latency_ms"] / total_req, 1) if total_req else 0,
        "last_request_at": info["last_request_at"],
        "mem": ps["mem"], "cpu": ps["cpu"],
        "tail": info["logs"].tail(4),
    }


@app.route("/api/list")
@login_required
def api_list():
    now = time.time()
    with lock:
        infos = [registry[k] for k in sorted(registry)]
    return jsonify({
        "apps": [app_summary(i, now) for i in infos],
        "system": system_stats(),
        "telegram": {"alerts": TELEGRAM_ENABLED, "control": TELEGRAM_CONTROL},
    })


@app.route("/api/logs/<name>")
@login_required
def api_logs(name):
    info = registry.get(name)
    if not info:
        return jsonify({"error": "not found"}), 404
    if request.args.get("format") == "text":
        lines, *_ = info["logs"].read(0, info["logs"].epoch)
        return Response("\n".join(lines) + "\n", mimetype="text/plain",
                        headers={"Content-Disposition": f'attachment; filename="{name}-logs.txt"'})
    try:
        since = int(request.args.get("since", 0))
        epoch = int(request.args.get("epoch", -1))
    except ValueError:
        since, epoch = 0, -1
    lines, last, ep, reset = info["logs"].read(since, epoch)
    return jsonify({"status": info["status"], "logs": lines, "last": last, "epoch": ep, "reset": reset})


@app.route("/api/logs/<name>/clear", methods=["POST"])
@login_required
def api_logs_clear(name):
    info = registry.get(name)
    if not info:
        return jsonify({"error": "not found"}), 404
    info["logs"].clear()
    return jsonify({"name": name})


@app.route("/api/requirements/<name>", methods=["GET"])
@login_required
def get_requirements(name):
    info = registry.get(name)
    if not info:
        return jsonify({"error": "not found"}), 404
    try:
        with open(os.path.join(info["dir"], "requirements.txt"), encoding="utf-8") as f:
            return jsonify({"content": f.read()})
    except OSError:
        return jsonify({"content": ""})


@app.route("/api/requirements/<name>", methods=["POST"])
@login_required
def save_requirements(name):
    info = registry.get(name)
    if not info:
        return jsonify({"error": "not found"}), 404
    content = (request.get_json(silent=True) or {}).get("content", "")
    path = os.path.join(info["dir"], "requirements.txt")
    if content.strip():
        with open(path, "w", encoding="utf-8") as f:
            f.write(content.strip() + "\n")
    elif os.path.exists(path):
        os.remove(path)
    info["_fs"] = None
    return jsonify({"name": name})


@app.route("/api/env/<name>", methods=["GET"])
@login_required
def get_env(name):
    info = registry.get(name)
    if not info:
        return jsonify({"error": "not found"}), 404
    return jsonify({"content": "\n".join(f"{k}={v}" for k, v in info["env"].items())})


@app.route("/api/env/<name>", methods=["POST"])
@login_required
def save_env(name):
    info = registry.get(name)
    if not info:
        return jsonify({"error": "not found"}), 404
    try:
        env = parse_env_text((request.get_json(silent=True) or {}).get("content", ""))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    env.pop("PORT", None)
    env.pop("HOST", None)
    with lock:
        info["env"] = env
        save_meta(info)
    return jsonify({"name": name, "count": len(env)})


@app.route("/api/auto_restart/<name>", methods=["POST"])
@login_required
def set_auto_restart(name):
    info = registry.get(name)
    if not info:
        return jsonify({"error": "not found"}), 404
    with lock:
        info["auto_restart"] = bool((request.get_json(silent=True) or {}).get("enabled"))
        info["restart_times"] = []
        save_meta(info)
    return jsonify({"name": name, "auto_restart": info["auto_restart"]})


@app.route("/api/password/<name>", methods=["POST"])
@login_required
def set_password(name):
    data = request.get_json(silent=True) or {}
    protected = bool(data.get("protected"))
    pw = (data.get("password") or "").strip()
    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        if not protected:
            info["protected"], info["password_hash"] = False, None
        else:
            if pw:
                info["password_hash"] = generate_password_hash(pw)
            if not info["password_hash"]:
                return jsonify({"error": "set a password first"}), 400
            info["protected"] = True
        save_meta(info)
    return jsonify({"name": name, "protected": info["protected"]})


@app.route("/api/upload", methods=["POST"])
@login_required
def upload_new():
    file = request.files.get("file")
    if not file or not file.filename.lower().endswith(".py"):
        return jsonify({"error": "Please upload a .py file"}), 400
    return jsonify(deploy_py(file.filename, file.read()))


@app.route("/api/upload/zip", methods=["POST"])
@login_required
def upload_zip():
    file = request.files.get("file")
    if not file or not file.filename.lower().endswith(".zip"):
        return jsonify({"error": "Please upload a .zip file"}), 400
    with tempfile.TemporaryDirectory() as tmp:
        zpath = os.path.join(tmp, "upload.zip")
        file.save(zpath)
        try:
            return jsonify(deploy_zip(file.filename, zpath))
        except ValueError as e:
            return jsonify({"error": str(e)}), 400


@app.route("/api/upload/<name>/file", methods=["POST"])
@login_required
def upload_extra_file(name):
    info = registry.get(name)
    if not info:
        return jsonify({"error": "not found"}), 404
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "no file provided"}), 400
    sj = safe_join(info["dir"], request.form.get("relpath") or file.filename)
    if not sj:
        return jsonify({"error": "invalid path"}), 400
    os.makedirs(os.path.dirname(sj[0]), exist_ok=True)
    file.save(sj[0])
    info["_fs"] = None
    if sj[1] == "requirements.txt":
        info["installed_hash"] = None
    return jsonify({"name": name, "file": sj[1]})


@app.route("/api/entry/<name>", methods=["POST"])
@login_required
def set_entry(name):
    entry = ((request.get_json(silent=True) or {}).get("entry") or "").strip()
    if not entry.endswith(".py"):
        return jsonify({"error": "entry point must be a .py file"}), 400
    with lock:
        info = registry.get(name)
        if not info:
            return jsonify({"error": "not found"}), 404
        sj = safe_join(info["dir"], entry)
        if not sj or not os.path.isfile(sj[0]):
            return jsonify({"error": "that file doesn't exist in this app's folder"}), 400
        info["entry"] = sj[1]
        save_meta(info)
    return jsonify({"name": name, "entry": sj[1]})


@app.route("/api/file/<name>/<path:filename>", methods=["DELETE"])
@login_required
def delete_file(name, filename):
    info = registry.get(name)
    if not info:
        return jsonify({"error": "not found"}), 404
    sj = safe_join(info["dir"], filename)
    if not sj:
        return jsonify({"error": "invalid path"}), 400
    if sj[1] == info["entry"]:
        return jsonify({"error": "can't delete the entry file — change the entry point or delete the app"}), 400
    try:
        os.remove(sj[0])
    except OSError:
        pass
    info["_fs"] = None
    if sj[1] == "requirements.txt":
        info["installed_hash"] = None
    return jsonify({"name": name, "file": sj[1]})


@app.route("/api/filecontent/<name>", methods=["GET"])
@login_required
def read_file_content(name):
    info = registry.get(name)
    if not info:
        return jsonify({"error": "not found"}), 404
    sj = safe_join(info["dir"], request.args.get("path", ""))
    if not sj or not os.path.isfile(sj[0]):
        return jsonify({"error": "file not found"}), 404
    if os.path.getsize(sj[0]) > 1024 * 1024:
        return jsonify({"error": "file is larger than 1 MB — can't edit here"}), 400
    with open(sj[0], "rb") as f:
        raw = f.read()
    try:
        if b"\0" in raw:
            raise UnicodeDecodeError("utf-8", b"", 0, 1, "binary")
        return jsonify({"path": sj[1], "content": raw.decode("utf-8")})
    except UnicodeDecodeError:
        return jsonify({"error": "binary file — can't show as text"}), 400


@app.route("/api/filecontent/<name>", methods=["POST"])
@login_required
def write_file_content(name):
    info = registry.get(name)
    if not info:
        return jsonify({"error": "not found"}), 404
    data = request.get_json(silent=True) or {}
    sj = safe_join(info["dir"], data.get("path", ""))
    if not sj:
        return jsonify({"error": "invalid path"}), 400
    content = data.get("content", "")
    if not isinstance(content, str) or len(content) > 2_000_000:
        return jsonify({"error": "content too large"}), 400
    os.makedirs(os.path.dirname(sj[0]), exist_ok=True)
    with open(sj[0], "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    info["_fs"] = None
    if sj[1] == "requirements.txt":
        info["installed_hash"] = None
    return jsonify({"name": name, "path": sj[1]})


@app.route("/api/download/<name>")
@login_required
def download_app(name):
    buf = zip_app_bytes(name)
    if buf is None:
        return jsonify({"error": "not found"}), 404
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=f"{name}.zip")


@app.route("/api/start/<name>", methods=["POST"])
@login_required
def start(name):
    ok, msg = start_app(name)
    if not ok:
        return jsonify({"error": msg}), 404 if msg == "not found" else 400
    return jsonify({"name": name, "url": f"/{name}/"})


@app.route("/api/stop/<name>", methods=["POST"])
@login_required
def stop(name):
    ok, msg = stop_app(name)
    return (jsonify({"name": name}) if ok else (jsonify({"error": msg}), 404))


@app.route("/api/restart/<name>", methods=["POST"])
@login_required
def restart(name):
    ok, msg = restart_app(name)
    if not ok:
        return jsonify({"error": msg}), 404 if msg == "not found" else 400
    return jsonify({"name": name, "url": f"/{name}/"})


@app.route("/api/delete/<name>", methods=["POST"])
@login_required
def delete(name):
    if not delete_app(name):
        return jsonify({"error": "not found"}), 404
    return jsonify({"name": name})


# ======================================================================================
#  Per-app password gate + reverse proxy  (/<name>/...)
# ======================================================================================

app_pass_signer = URLSafeTimedSerializer(app.secret_key, salt="app-pass-v1")
APP_PASS_COOKIE_TTL = 60 * 60 * 12


def app_pass_cookie_name(name):
    return f"apw_{name}"


def has_valid_app_cookie(name):
    cookie = request.cookies.get(app_pass_cookie_name(name))
    if not cookie:
        return False
    try:
        return app_pass_signer.loads(cookie, max_age=APP_PASS_COOKIE_TTL).get("app") == name
    except (BadSignature, SignatureExpired):
        return False


def wants_html():
    accept = request.headers.get("Accept") or ""
    if "text/html" in accept:
        return True
    return accept.strip() == "*/*" and "Mozilla" in (request.headers.get("User-Agent") or "")


@app.route("/<name>/", defaults={"subpath": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@app.route("/<name>/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def proxy(name, subpath):
    if name.lower() in RESERVED_NAMES:
        return jsonify({"error": "not found"}), 404
    info = registry.get(name)
    if not info or info["status"] not in ("running", "starting"):
        return jsonify({"error": "This app is not running"}), 502
    if fs_info(info)["kind"] == "bot":
        return jsonify({"error": "This is a background bot — it has no web page."}), 404
    html_client = wants_html()

    if info["protected"] and not has_valid_app_cookie(name):
        bucket = f"{client_ip()}:{name}"
        remaining_lock = app_pass_limiter.locked_for(bucket)
        if remaining_lock > 0:
            if html_client and request.method == "GET":
                m, s = divmod(int(remaining_lock), 60)
                return render_page("app_lock.html", name=name, error=f"Too many attempts. Try again in {m}m {s}s.",
                                   locked=True), 429
            return jsonify({"error": "too many attempts — try again later"}), 429

        supplied = request.args.get("pass") or request.headers.get("X-Api-Pass", "")
        if supplied and info["password_hash"] and check_password_hash(info["password_hash"], supplied):
            app_pass_limiter.reset(bucket)
            if html_client and request.method == "GET":
                clean_qs = [(k, v) for k, v in request.args.items(multi=True) if k != "pass"]
                target = f"/{name}/{subpath}" + ("?" + urlencode(clean_qs) if clean_qs else "")
                resp = redirect(target)
                resp.set_cookie(app_pass_cookie_name(name), app_pass_signer.dumps({"app": name}),
                                max_age=APP_PASS_COOKIE_TTL, httponly=True, samesite="Lax",
                                secure=app.config["SESSION_COOKIE_SECURE"])
                return resp
        elif supplied:
            remaining, locked_now = app_pass_limiter.fail(bucket)
            if html_client and request.method == "GET":
                msg = "Locked — too many attempts, try again later." if locked_now else f"Incorrect password. {remaining} attempt(s) left."
                return render_page("app_lock.html", name=name, error=msg, locked=False), 401
            return jsonify({"error": "incorrect password"}), 401
        else:
            if html_client and request.method == "GET":
                return render_page("app_lock.html", name=name, error=None, locked=False), 401
            return jsonify({"error": "password required — add ?pass=yourpassword or an X-Api-Pass header"}), 401

    port = info["port"]
    if not port:
        return jsonify({"error": "app is still starting — try again in a moment"}), 503

    # Never forward the admin / unlock cookies or the access password to the hosted app.
    drop = {"host", "cookie", "x-api-pass", "content-length"}
    fwd = {k: v for k, v in request.headers if k.lower() not in drop}
    fwd["X-Forwarded-For"] = client_ip()
    fwd["X-Forwarded-Proto"] = request.scheme
    fwd["X-Forwarded-Host"] = request.host
    fwd["X-Forwarded-Prefix"] = f"/{name}"

    start_t = time.time()
    try:
        upstream = http_session.request(
            method=request.method, url=f"http://127.0.0.1:{port}/{subpath}",
            headers=fwd, data=request.get_data(),
            params=[(k, v) for k, v in request.args.items(multi=True) if k != "pass"],
            timeout=(5, 60),
            allow_redirects=False,  # FIX: redirects were followed server-side, breaking Location/cookies
        )
        status_code = upstream.status_code
        latency_ms = (time.time() - start_t) * 1000
        _count_request(name, status_code, latency_ms, f"{request.method} /{subpath}")

        skip = {"content-encoding", "content-length", "transfer-encoding", "connection"}
        headers = []
        for k, v in upstream.raw.headers.items():
            if k.lower() in skip:
                continue
            if k.lower() == "location" and v.startswith("/") and not v.startswith("//"):
                v = f"/{name}{v}"  # keep redirects inside this app's URL prefix
            headers.append((k, v))
        return Response(upstream.content, status_code, headers)
    except requests.exceptions.RequestException as e:
        _count_request(name, 502, (time.time() - start_t) * 1000, f"{request.method} /{subpath}", err=str(e)[:120])
        return jsonify({"error": f"upstream error: {e}"}), 502


def _count_request(name, status, latency_ms, label, err=None):
    info = registry.get(name)
    if not info:
        return
    with lock:
        info["total_requests"] += 1
        info["total_latency_ms"] += latency_ms
        info["request_times"].append(time.time())
        info["last_request_at"] = time.time()
        info["error_count" if status >= 400 else "success_count"] += 1
    info["logs"].add(f"[req] {label} → {status if not err else 'ERROR'}  {latency_ms:.0f}ms  from {client_ip()}"
                     + (f"  ({err})" if err else ""))


# ======================================================================================
#  Telegram control bot  (manage everything from your phone)
# ======================================================================================

STATUS_EMOJI = {"running": "🟢", "starting": "🟡", "installing": "🟡", "stopped": "⚪", "crashed": "🔴"}
esc = html.escape

HELP_TEXT = (
    "🤖 <b>API Manager control bot</b>\n\n"
    "/apps — all apps with buttons\n"
    "/status — server stats\n"
    "/run <i>name</i> · /stop <i>name</i> · /restart <i>name</i>\n"
    "/logs <i>name</i> [lines] — recent output\n"
    "/backup <i>name</i> — get the app as a .zip\n\n"
    "📤 <b>Deploy:</b> send me a <code>.py</code> or <code>.zip</code> file. "
    "Put an existing app's name in the caption to update that app instead of creating a new one."
)


def tg_apps_view():
    with lock:
        infos = [registry[k] for k in sorted(registry)]
    if not infos:
        return "No apps yet. Send me a .py or .zip file to deploy one.", None
    lines, rows = [], []
    for i in infos:
        up = f" · up {fmt_uptime(time.time() - i['started_at'])}" if i["status"] == "running" and i["started_at"] else ""
        kind = " 🤖" if fs_info(i)["kind"].startswith("bot") else ""
        lines.append(f"{STATUS_EMOJI.get(i['status'], '⚪')} <b>{esc(i['name'])}</b>{kind} — {i['status']}{up}")
        n = i["name"]
        rows.append([{"text": n[:14], "callback_data": f"info:{n}"},
                     {"text": "▶️", "callback_data": f"run:{n}"}, {"text": "⏹", "callback_data": f"stop:{n}"},
                     {"text": "🔄", "callback_data": f"restart:{n}"}, {"text": "📜", "callback_data": f"logs:{n}"}])
    return "\n".join(lines), {"inline_keyboard": rows}


def tg_status_text():
    s = system_stats()
    with lock:
        infos = list(registry.values())
    run = sum(1 for i in infos if i["status"] in ("running", "starting", "installing"))
    crash = sum(1 for i in infos if i["status"] == "crashed")
    mem = f"{s['mem_used'] / 1048576:.0f} / {s['mem_total'] / 1048576:.0f} MB" if s["mem_total"] else "n/a"
    cpu = f"{s['cpu']}%" if s["cpu"] is not None else "n/a"
    return (f"📊 <b>Server</b>\nRAM: {mem}\nCPU: {cpu}\nUp: {fmt_uptime(s['uptime'])}\n\n"
            f"Apps: {len(infos)} total · {run} running · {crash} crashed")


def tg_logs_text(name, n=30):
    info = registry.get(name)
    if not info:
        return f"No app called {esc(name)}."
    lines = info["logs"].tail(max(1, min(n, 150)))
    body = "\n".join(lines) or "(no output yet)"
    if len(body) > 3400:
        body = "…" + body[-3400:]
    return f"📜 <b>{esc(name)}</b> — {info['status']}\n<pre>{esc(body)}</pre>"


def tg_do(act, name):
    if name not in registry:
        return f"No app called {name}."
    if act == "run":
        ok, msg = start_app(name)
    elif act == "stop":
        ok, msg = stop_app(name)
    else:
        ok, msg = restart_app(name)
    return f"{'✅' if ok else '⚠️'} {name}: {msg}"


def tg_send_backup(name):
    buf = zip_app_bytes(name)
    if buf is None:
        send_telegram(f"No app called {esc(name)}.", True)
        return
    data = buf.getvalue()
    if len(data) > 49 * 1024 * 1024:
        send_telegram("⚠️ That app is bigger than Telegram's 50 MB bot upload limit.")
        return
    tg_call("sendDocument", chat_id=TELEGRAM_CHAT_ID, caption=f"Backup of {name}",
            files={"document": (f"{name}.zip", data)})


def tg_handle_document(msg):
    doc = msg["document"]
    fname = doc.get("file_name", "")
    low = fname.lower()
    if not (low.endswith(".py") or low.endswith(".zip")):
        send_telegram("Send a .py or .zip file to deploy it.")
        return
    if doc.get("file_size", 0) > 20 * 1024 * 1024:
        send_telegram("⚠️ Telegram bots can only download files up to 20 MB.")
        return
    info = tg_call("getFile", file_id=doc["file_id"])
    if not info.get("ok"):
        send_telegram("⚠️ Couldn't fetch that file from Telegram.")
        return
    try:
        raw = requests.get(f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{info['result']['file_path']}",
                           timeout=60).content
    except Exception as e:
        send_telegram(f"⚠️ Download failed: {e}")
        return
    target = (msg.get("caption") or "").strip().split()[0] if (msg.get("caption") or "").strip() else None
    try:
        if low.endswith(".py"):
            res = deploy_py(fname, raw, target)
        else:
            with tempfile.TemporaryDirectory() as tmp:
                zp = os.path.join(tmp, "u.zip")
                with open(zp, "wb") as f:
                    f.write(raw)
                res = deploy_zip(fname, zp, target)
    except ValueError as e:
        send_telegram(f"⚠️ {e}")
        return
    name = res["name"]
    if res["existing"]:
        restart_app(name) if registry[name]["status"] in ("running", "starting", "installing") else None
        send_telegram(f"♻️ Updated <b>{esc(name)}</b> (entry: {esc(res['entry'])}).", True)
    else:
        send_telegram(f"✅ Deployed <b>{esc(name)}</b> (entry: {esc(res['entry'])}).\nTap /apps to start it.", True)


def tg_handle_update(u):
    if "callback_query" in u:
        cq = u["callback_query"]
        if str(cq["message"]["chat"]["id"]) != str(TELEGRAM_CHAT_ID):
            return tg_call("answerCallbackQuery", callback_query_id=cq["id"], text="Not authorised")
        act, _, name = cq["data"].partition(":")
        note = ""
        if act in ("run", "stop", "restart"):
            note = tg_do(act, name)
            time.sleep(0.6)
        elif act == "logs":
            send_telegram(tg_logs_text(name), True)
        elif act == "info":
            i = registry.get(name)
            note = f"{name}: {i['status']}" if i else "gone"
        tg_call("answerCallbackQuery", callback_query_id=cq["id"], text=note[:190])
        if act in ("run", "stop", "restart"):
            text, markup = tg_apps_view()
            params = {"chat_id": cq["message"]["chat"]["id"], "message_id": cq["message"]["message_id"],
                      "text": text, "parse_mode": "HTML"}
            if markup:
                params["reply_markup"] = json.dumps(markup)
            tg_call("editMessageText", **params)
        return

    msg = u.get("message")
    if not msg:
        return
    if str(msg["chat"]["id"]) != str(TELEGRAM_CHAT_ID):
        tg_call("sendMessage", chat_id=msg["chat"]["id"], text="⛔ Not authorised.")
        return
    if "document" in msg:
        return tg_handle_document(msg)

    parts = (msg.get("text") or "").strip().split()
    if not parts or not parts[0].startswith("/"):
        return
    cmd = parts[0].split("@")[0].lower()
    arg = parts[1] if len(parts) > 1 else ""
    if cmd in ("/start", "/help"):
        send_telegram(HELP_TEXT, True)
    elif cmd in ("/apps", "/list"):
        text, markup = tg_apps_view()
        send_telegram(text, True, markup)
    elif cmd == "/status":
        send_telegram(tg_status_text(), True)
    elif cmd in ("/run", "/stop", "/restart"):
        send_telegram(esc(tg_do(cmd[1:], arg)) if arg else f"Usage: {cmd} <name>", True)
    elif cmd == "/logs":
        if not arg:
            send_telegram("Usage: /logs <name> [lines]")
        else:
            n = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 30
            send_telegram(tg_logs_text(arg, n), True)
    elif cmd == "/backup":
        tg_send_backup(arg) if arg else send_telegram("Usage: /backup <name>")
    else:
        send_telegram("Unknown command. Try /help")


def telegram_control_loop():
    offset = None
    print("Telegram control bot: ENABLED (send /help to your bot)")
    tg_call("deleteWebhook")
    while True:
        try:
            params = {"timeout": 25, "allowed_updates": json.dumps(["message", "callback_query"])}
            if offset:
                params["offset"] = offset
            data = requests.get(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates",
                                params=params, timeout=40).json()
            if not data.get("ok"):
                if data.get("error_code") == 409:
                    print("Telegram control bot: 409 conflict — another program is polling this bot token.")
                    time.sleep(30)
                else:
                    time.sleep(5)
                continue
            for u in data["result"]:
                offset = u["update_id"] + 1
                try:
                    tg_handle_update(u)
                except Exception as e:
                    print("telegram handler error:", e)
        except Exception:
            time.sleep(5)


# ======================================================================================
#  Background startup: restore apps, control bot, optional keep-alive ping
# ======================================================================================

def restore_apps():
    time.sleep(1)
    with lock:
        names = [n for n, i in registry.items() if i["desired"]]
    for n in names:
        print(f"restoring {n} …")
        start_app(n)
        time.sleep(1.0)  # stagger so a pile of installs doesn't hit at once


def keepalive_loop():
    url = os.environ.get("SELF_PING_URL") or os.environ.get("RENDER_EXTERNAL_URL")
    if not url:
        return
    while True:
        time.sleep(600)
        try:
            requests.get(url.rstrip("/") + "/healthz", timeout=15)
        except Exception:
            pass


_bg_started = False


def start_background():
    global _bg_started
    if _bg_started:
        return
    _bg_started = True
    threading.Thread(target=restore_apps, daemon=True).start()
    if TELEGRAM_CONTROL:
        threading.Thread(target=telegram_control_loop, daemon=True).start()
    if os.environ.get("KEEP_ALIVE") == "1":
        threading.Thread(target=keepalive_loop, daemon=True).start()
    if psutil:
        psutil.cpu_percent(None)  # prime the counter


print("Telegram alerts + OTP login:", "ENABLED" if TELEGRAM_ENABLED else "disabled (set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)")
start_background()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    try:
        from waitress import serve
        print(f"Serving with waitress on :{port}")
        serve(app, host="0.0.0.0", port=port, threads=int(os.environ.get("THREADS", "32")),
              channel_timeout=120, max_request_body_size=300 * 1024 * 1024)
    except ImportError:
        print("waitress not installed — using Flask's dev server (pip install waitress for production).")
        app.run(host="0.0.0.0", port=port, threaded=True)
