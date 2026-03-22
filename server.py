from flask import Flask, request, jsonify, Response
import requests
import sqlite3
import hashlib
import uuid
import base64
from datetime import datetime, timezone

app = Flask(__name__)
@app.route("/")
def health():
    return "OK", 200

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Username, X-Local-Date'
    return response

@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        res = Response()
        res.headers['Access-Control-Allow-Origin'] = '*'
        res.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        res.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Username, X-Local-Date'
        return res, 200

import os
DB = os.environ.get("DB_PATH", "nutritrack.db")

# ── Database ──────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            conversation_id TEXT NOT NULL
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            role TEXT,
            text TEXT,
            log_date TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        # Add log_date column if upgrading from old DB
        try:
            conn.execute("ALTER TABLE messages ADD COLUMN log_date TEXT")
        except Exception:
            pass
        # Add email column for Google auth
        try:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        except Exception:
            pass
        conn.commit()

init_db()

# ── Helpers ───────────────────────────────────

def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_current_user():
    return request.headers.get("X-Username")

# ── Register ──────────────────────────────────

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").lower().strip()
    email    = data.get("email", "").lower().strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    with get_db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            return jsonify({"error": "Username already exists"}), 409
        if email and conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            return jsonify({"error": "Email already registered"}), 409

        conv_id = f"user-{username}-{uuid.uuid4().hex[:8]}"
        conn.execute(
            "INSERT INTO users (username, password, conversation_id, email) VALUES (?,?,?,?)",
            (username, hash_pw(password), conv_id, email or None)
        )
        conn.commit()

    return jsonify({"username": username})

# ── Login ─────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email    = data.get("email", "").lower().strip()
    username = data.get("username", "").lower().strip()
    password = data.get("password", "")

    with get_db() as conn:
        # Support login by email OR username
        if email:
            user = conn.execute("SELECT * FROM users WHERE email=? OR username=?", (email, email)).fetchone()
        else:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not user:
            return jsonify({"error": "Account not found"}), 404
        if user["password"] == "GOOGLE_AUTH":
            return jsonify({"error": "This account uses Google Sign-In. Please use Continue with Google."}), 401
        if user["password"] != hash_pw(password):
            return jsonify({"error": "Wrong password"}), 401

        today = request.headers.get("X-Local-Date", datetime.now().strftime("%Y-%m-%d"))
        msgs = conn.execute(
            "SELECT role, text, log_date FROM messages WHERE username=? ORDER BY created_at",
            (user["username"],)
        ).fetchall()
        history = [{"role": m["role"], "text": m["text"], "log_date": m["log_date"]} for m in msgs]

    return jsonify({"username": user["username"], "history": history, "today": today})

# ── Google Auth ───────────────────────────────
@app.route("/google-auth", methods=["POST", "OPTIONS"])
def google_auth():
    if request.method == "OPTIONS":
        return Response(status=200)
    data = request.json
    email    = data.get("email", "").lower().strip()
    username = data.get("username", email.split("@")[0]).strip()

    if not email:
        return jsonify({"error": "Email required"}), 400

    # Sanitize username — only alphanumeric + underscores
    import re
    username = re.sub(r'[^a-zA-Z0-9_]', '_', username)[:20]

    with get_db() as conn:
        # Check if user exists by email
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

        if not user:
            # New user — register them
            # Ensure unique username
            base = username
            counter = 1
            while conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                username = f"{base}_{counter}"
                counter += 1
            conn.execute(
                "INSERT INTO users (username, password, email, conversation_id) VALUES (?, ?, ?, ?)",
                (username, "GOOGLE_AUTH", email, str(uuid.uuid4()))
            )
            conn.commit()
        else:
            username = user["username"]

        today = request.headers.get("X-Local-Date", datetime.now().strftime("%Y-%m-%d"))
        msgs = conn.execute(
            "SELECT role, text, log_date FROM messages WHERE username=? ORDER BY created_at",
            (username,)
        ).fetchall()
        history = [{"role": m["role"], "text": m["text"], "log_date": m["log_date"]} for m in msgs]

    return jsonify({"username": username, "history": history, "today": today})

# ── History ───────────────────────────────────

@app.route("/history", methods=["GET"])
def history():
    username = get_current_user()
    if not username:
        return jsonify({"error": "Not logged in"}), 401

    # Get client's local date from header (sent by frontend)
    today = request.headers.get("X-Local-Date", datetime.now().strftime("%Y-%m-%d"))

    with get_db() as conn:
        msgs = conn.execute(
            "SELECT role, text, log_date FROM messages WHERE username=? ORDER BY created_at",
            (username,)
        ).fetchall()
        history = [{"role": m["role"], "text": m["text"], "log_date": m["log_date"]} for m in msgs]

    return jsonify({"username": username, "history": history, "today": today})

# ── AI Chat ───────────────────────────────────

SIM_API_KEY = "sk-sim-XoyEvRSZkbdyFmeZaR5s7EF6VoSoAszP"
WORKFLOW_ID  = "1242b3a8-390b-40f3-be79-2484f4281f53"
API_URL      = f"https://www.sim.ai/api/workflows/{WORKFLOW_ID}/execute"


@app.route("/chat", methods=["POST"])
def chat():
    username = get_current_user()
    if not username:
        return jsonify({"error": "Not logged in"}), 401

    try:
        # Support both JSON (text only) and multipart/form-data (text + image)
        content_type = request.content_type or ""

        if "multipart/form-data" in content_type:
            user_input = request.form.get("message", "")
            image_file = request.files.get("image")
        else:
            user_input = request.json.get("message", "")
            image_file = None

        with get_db() as conn:
            row = conn.execute(
                "SELECT conversation_id FROM users WHERE username=?", (username,)
            ).fetchone()
            conv_id = row["conversation_id"]

        # Get client local date
        today = request.headers.get("X-Local-Date", datetime.now().strftime("%Y-%m-%d"))

        # Inject today's date into the message so the agent is always date-aware
        dated_input = f"[Date: {today}] {user_input}"

        # Build payload
        payload = {
            "input": dated_input,
            "conversationId": conv_id
        }

        # Attach image as base64 if provided
        if image_file:
            image_data  = image_file.read()
            b64         = base64.b64encode(image_data).decode("utf-8")
            payload["files"] = [{
                "name":   image_file.filename,
                "base64": b64,
                "type":   image_file.mimetype
            }]

        response = requests.post(
            API_URL,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": SIM_API_KEY
            },
            json=payload
        )

        print("SIM RESPONSE:", response.text)

        data = response.json()
        bot_reply = ""
        if "output" in data:
            bot_reply = data["output"].get("content", "")
        if not bot_reply:
            bot_reply = str(data)

        # Save to DB — note what the user sent
        display_input = f"[Image] {user_input}" if image_file else user_input

        with get_db() as conn:
            conn.execute(
                "INSERT INTO messages (username,role,text,log_date) VALUES (?,?,?,?)",
                (username, "user", display_input, today)
            )
            conn.execute(
                "INSERT INTO messages (username,role,text,log_date) VALUES (?,?,?,?)",
                (username, "bot", bot_reply, today)
            )
            conn.commit()

        return jsonify({"output": {"content": bot_reply}})

    except Exception as e:
        print("ERROR:", e)
        return jsonify({"error": str(e)}), 500


# ── Run ───────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
app.run(host="0.0.0.0", port=port, debug=False)
