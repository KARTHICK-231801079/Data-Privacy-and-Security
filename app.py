"""
Healthcare Data Privacy & Security Demo Application
Demonstrates role-based access control, MFA, and security logging
"""

import base64
import io
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import pyotp
import qrcode
import qrcode.image.svg
from flask import Flask, flash, g, redirect, render_template, request, session, url_for

# ============================================================================
# Configuration
# ============================================================================
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "users.db")
SESSION_TIMEOUT = 15 * 60  # 15 minutes
BRUTE_FORCE_THRESHOLD = 5
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 10 * 60  # 10 minutes rolling window

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(seconds=SESSION_TIMEOUT)

failed_attempts = defaultdict(list)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def utc_now_ts():
    return datetime.now(timezone.utc).timestamp()


# ============================================================================
# Database Functions
# ============================================================================
def get_db():
    """Get database connection, creating if necessary."""
    if not hasattr(g, "db"):
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def execute_db(query, args=()):
    """Execute INSERT, UPDATE, DELETE query."""
    db = get_db()
    cur = db.cursor()
    cur.execute(query, args)
    db.commit()
    return cur.lastrowid


def query_db(query, args=(), one=False):
    """Execute SELECT query, return single row or all rows."""
    cur = get_db().execute(query, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


@app.teardown_appcontext
def close_db(e=None):
    """Close database connection."""
    if hasattr(g, "db"):
        g.db.close()


# ============================================================================
# Database Initialization
# ============================================================================
def init_db():
    """Initialize database with required tables and default admin user."""
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            role TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)

    # Security logs table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            username TEXT,
            ip_address TEXT,
            message TEXT NOT NULL,
            event_time TEXT NOT NULL,
            severity TEXT DEFAULT 'info'
        )
    """)

    # Ensure all required columns exist in security_logs
    security_log_columns = [col[1] for col in cur.execute("PRAGMA table_info(security_logs)")]
    if "ip_address" not in security_log_columns:
        cur.execute("ALTER TABLE security_logs ADD COLUMN ip_address TEXT")
    if "severity" not in security_log_columns:
        cur.execute("ALTER TABLE security_logs ADD COLUMN severity TEXT DEFAULT 'info'")

    # Ensure all required columns exist in users
    user_columns = [col[1] for col in cur.execute("PRAGMA table_info(users)")]
    if "last_login" not in user_columns:
        cur.execute("ALTER TABLE users ADD COLUMN last_login TEXT")

    # Create default admin user
    admin = cur.execute("SELECT * FROM users WHERE username='admin'").fetchone()
    if not admin:
        password_hash = bcrypt.hashpw(b"AdminPass123!", bcrypt.gensalt())
        secret = pyotp.random_base32()
        cur.execute("""
            INSERT INTO users (username, password_hash, role, totp_secret, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, ("admin", password_hash, "Admin", secret, utc_now_iso()))
        print("✅ Default Admin Created")
        print("   Username: admin")
        print("   Password: AdminPass123!")

    db.commit()
    db.close()

# ============================================================================
# Utility Functions
# ============================================================================
def log_event(event_type, username, message, severity="info"):
    """Log security event to database with IP address and timestamp."""
    ip = request.remote_addr if request else "system"
    execute_db("""
        INSERT INTO security_logs (event_type, username, ip_address, message, event_time, severity)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (event_type, username, ip, message, utc_now_iso(), severity))


def generate_qr_code(data):
    """Generate QR code SVG from data string."""
    qr = qrcode.QRCode(box_size=4, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
    buffer = io.BytesIO()
    img.save(buffer)
    return "data:image/svg+xml;base64," + base64.b64encode(buffer.getvalue()).decode()


def login_required(f):
    """Decorator to require login for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def role_required(required_role):
    """Decorator to require specific role for protected routes."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in first", "warning")
                return redirect(url_for("login"))
            if session.get("role") != required_role and session.get("role") != "Admin":
                log_event("Unauthorized Access", session.get("username"), 
                         f"Attempted to access {required_role} resource", "warning")
                return redirect(url_for("access_denied", message=f"This page is for {required_role}s only"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============================================================================
# Routes
# ============================================================================
@app.route("/")
def index():
    """Home page - redirect to login."""
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register new user and set up MFA."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "").strip()

        # Validation
        if not username or not password or not role:
            flash("All fields are required", "danger")
            return redirect(url_for("register"))

        if len(username) < 3:
            flash("Username must be at least 3 characters", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters", "danger")
            return redirect(url_for("register"))

        if query_db("SELECT * FROM users WHERE username=?", (username,), one=True):
            flash("Username already exists", "danger")
            log_event("Registration Failed", username, "Username already taken", "warning")
            return redirect(url_for("register"))

        # Create new user
        try:
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            secret = pyotp.random_base32()

            execute_db("""
                INSERT INTO users (username, password_hash, role, totp_secret, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (username, password_hash, role, secret, utc_now_iso()))

            log_event("Registration", username, f"New {role} account created", "info")

            # Generate QR code for TOTP setup
            uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Healthcare Security")
            qr = generate_qr_code(uri)

            session["reg_user"] = username
            session["reg_secret"] = secret

            return render_template("register.html", show_qr=True,
                                 qr_code_src=qr, username=username, totp_secret=secret)

        except Exception as e:
            log_event("Registration Error", username, str(e), "error")
            flash("Registration failed. Please try again", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/verify_registration", methods=["POST"])
def verify_registration():
    """Verify TOTP code during registration."""
    username = session.get("reg_user")
    secret = session.get("reg_secret")

    if not username or not secret:
        flash("Session expired. Please register again", "danger")
        return redirect(url_for("register"))

    code = request.form.get("otp", "").strip()

    try:
        if pyotp.TOTP(secret).verify(code):
            log_event("MFA Setup", username, "TOTP verification successful", "info")
            session.clear()
            flash("MFA setup complete! You can now login.", "success")
            return redirect(url_for("login"))
        else:
            flash("Invalid OTP. Please try again", "danger")
            return redirect(url_for("register"))
    except Exception as e:
        log_event("MFA Setup Error", username, str(e), "error")
        flash("Verification failed. Please try again", "danger")
        return redirect(url_for("register"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login with username and password."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = query_db("SELECT * FROM users WHERE username=?", (username,), one=True)

        if not user or not bcrypt.checkpw(password.encode(), user["password_hash"]):
            now_ts = utc_now_ts()
            failed_attempts[username] = [t for t in failed_attempts[username] if now_ts - t < LOCKOUT_DURATION]
            failed_attempts[username].append(now_ts)

            count = len(failed_attempts[username])
            severity = "critical" if count >= MAX_FAILED_ATTEMPTS else "warning"

            if count >= MAX_FAILED_ATTEMPTS:
                log_event("Brute Force Alert", username, f"{count} failed attempts in rolling window", "critical")

            log_event("Failed Login", username, f"Attempt #{count}", severity)
            flash(f"Invalid username or password ({count} attempts)", "danger")
            return redirect(url_for("login"))

        # Clear failed attempts on successful password check
        failed_attempts[username] = []

        # Move to OTP verification
        session["temp_user"] = user["id"]
        log_event("Login Step 1", username, "Password verified, proceeding to MFA", "info")
        return redirect(url_for("otp"))

    return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp():
    """OTP/TOTP verification for second factor authentication."""
    temp_user_id = session.get("temp_user")

    if not temp_user_id:
        flash("Please log in first", "warning")
        return redirect(url_for("login"))

    user = query_db("SELECT * FROM users WHERE id=?", (temp_user_id,), one=True)

    if not user:
        session.clear()
        flash("User not found", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()

        try:
            if pyotp.TOTP(user["totp_secret"]).verify(code):
                # Successful login
                session.clear()
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                session["username"] = user["username"]

                # Update last login time
                execute_db("UPDATE users SET last_login=? WHERE id=?",
                         (utc_now_iso(), user["id"]))

                log_event("Login Success", user["username"], "Successfully authenticated with MFA", "info")

                return redirect(url_for("dashboard"))
            else:
                log_event("Failed OTP", user["username"], "Invalid OTP code", "warning")
                flash("Invalid OTP. Please try again", "danger")

        except Exception as e:
            log_event("OTP Verification Error", user["username"], str(e), "error")
            flash("OTP verification failed", "danger")

    return render_template("otp.html", username=user["username"])


@app.route("/dashboard")
@login_required
def dashboard():
    """Main dashboard - routes based on user role."""
    role = session.get("role")
    username = session.get("username")

    if role == "Admin":
        return redirect(url_for("admin"))
    elif role == "Doctor":
        return redirect(url_for("doctor"))
    elif role == "Pharmacy":
        return redirect(url_for("pharmacy"))
    else:
        return render_template("dashboard.html", username=username, role=role)


@app.route("/admin")
@role_required("Admin")
def admin():
    users = query_db("SELECT username, role, created_at, last_login FROM users ORDER BY created_at DESC")
    logs = query_db("SELECT * FROM security_logs ORDER BY event_time DESC LIMIT 100")
    failed_summary = query_db("""
        SELECT username, COUNT(*) as attempts, MAX(event_time) as last_attempt
        FROM security_logs
        WHERE event_type='Failed Login' AND username IS NOT NULL
        GROUP BY username
        ORDER BY attempts DESC
        LIMIT 20
    """)
    flagged_users = [row for row in failed_summary if row["attempts"] >= MAX_FAILED_ATTEMPTS]
    return render_template(
        "admin.html",
        users=users,
        logs=logs,
        failed_summary=failed_summary,
        flagged_users=flagged_users,
        critical_threshold=MAX_FAILED_ATTEMPTS,
    )


@app.route("/doctor")
@role_required("Doctor")
def doctor():
    patients = [
        {"name": "John Doe", "condition": "Fever", "last_visit": "2026-04-28", "status": "Active", "risk": "Low", "next_visit": "2026-05-03"},
        {"name": "Priya S", "condition": "Diabetes", "last_visit": "2026-04-25", "status": "Follow-up", "risk": "Medium", "next_visit": "2026-05-02"},
        {"name": "Rajan M", "condition": "Hypertension", "last_visit": "2026-04-20", "status": "Stable", "risk": "Medium", "next_visit": "2026-05-06"},
        {"name": "Arun K", "condition": "Asthma", "last_visit": "2026-04-22", "status": "Critical", "risk": "High", "next_visit": "2026-04-30"},
    ]
    return render_template("doctor.html", username=session.get("username"), patients=patients)


@app.route("/pharmacy")
@role_required("Pharmacy")
def pharmacy():
    prescriptions = [
        {"patient": "John Doe", "medication": "Paracetamol", "qty": "10 tabs", "status": "Ready", "priority": "Normal"},
        {"patient": "Priya S", "medication": "Insulin", "qty": "1 vial", "status": "Pending", "priority": "High"},
        {"patient": "Rajan M", "medication": "Amlodipine", "qty": "30 tabs", "status": "Ready", "priority": "Normal"},
        {"patient": "Arun K", "medication": "Salbutamol", "qty": "2 inhalers", "status": "Urgent", "priority": "Critical"},
    ]
    return render_template("pharmacy.html", username=session.get("username"), prescriptions=prescriptions)


@app.route("/access_denied")
def access_denied():
    """Access denied page."""
    message = request.args.get("message", "You do not have permission to access this resource.")
    return render_template("access_denied.html", message=message), 403


@app.route("/logout")
def logout():
    """User logout."""
    username = session.get("username")
    log_event("Logout", username, "User logged out", "info")
    session.clear()
    flash("You have been logged out", "success")
    return redirect(url_for("login"))




# ============================================================================
# Application Entry Point
# ============================================================================
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="localhost", port=5000)