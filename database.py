"""
database.py
Database and User Management for NetTransfer
Provides SQLite user account management, secure password hashing,
input validation, and directory path assignment for multi-tenant FTP provisioning.
Course: Computer Networks and Ethical Hacking
"""

import os
import re
import sqlite3
from typing import Optional, Dict, Any, Tuple
from werkzeug.security import generate_password_hash, check_password_hash

# Default database location
DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "nettransfer.db"
)

# Base storage directory for isolated client files
DEFAULT_STORAGE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "demo_ftp_storage"
)

# Regex validation rules
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def get_db_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Creates a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initializes the database schema if not already created."""
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fullname TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                ftp_home_dir TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)")
        conn.commit()


def validate_registration_inputs(
    fullname: str,
    email: str,
    username: str,
    password: str,
    confirm_password: str
) -> Tuple[bool, str]:
    """
    Validates user registration input fields.
    Returns (is_valid, error_message).
    """
    fullname = (fullname or "").strip()
    email = (email or "").strip().lower()
    username = (username or "").strip()
    password = password or ""
    confirm_password = confirm_password or ""

    if not fullname or len(fullname) < 2 or len(fullname) > 80:
        return False, "Full name must be between 2 and 80 characters."

    if not email or not EMAIL_REGEX.match(email) or len(email) > 120:
        return False, "Please enter a valid email address."

    if not username or not USERNAME_REGEX.match(username):
        return False, "Username must be 3-30 characters long and contain only letters, numbers, and underscores."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    # Check that password has both letters and digits for security
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not (has_letter and has_digit):
        return False, "Password must contain both letters and numbers."

    if password != confirm_password:
        return False, "Passwords do not match."

    return True, ""


def register_user(
    fullname: str,
    email: str,
    username: str,
    password: str,
    confirm_password: str,
    db_path: str = DEFAULT_DB_PATH,
    storage_root: str = DEFAULT_STORAGE_PATH
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Registers a new website account and provisions their isolated FTP home directory.
    Passwords are encrypted using secure PBKDF2/scrypt password hashing.
    Returns (success, message, user_dict).
    """
    is_valid, err_msg = validate_registration_inputs(
        fullname=fullname,
        email=email,
        username=username,
        password=password,
        confirm_password=confirm_password
    )
    if not is_valid:
        return False, err_msg, None

    fullname = fullname.strip()
    email = email.strip().lower()
    username = username.strip()

    # Isolated home directory path for this specific client
    user_home_dir = os.path.join(storage_root, "users", username)

    # Secure password hash
    pw_hash = generate_password_hash(password, method="scrypt")

    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            # Check for existing username or email
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return False, f"Username '{username}' is already taken. Please choose another.", None

            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                return False, f"Email address '{email}' is already registered.", None

            # Provision the physical isolated home directory
            os.makedirs(user_home_dir, exist_ok=True)

            # Create an initial welcome note inside their private folder
            welcome_path = os.path.join(user_home_dir, "welcome.txt")
            if not os.path.exists(welcome_path):
                try:
                    with open(welcome_path, "w", encoding="utf-8") as f:
                        f.write(
                            f"Welcome to your private NetTransfer storage, {fullname}!\n"
                            "----------------------------------------------------------\n"
                            f"Account Username: {username}\n"
                            "Your files are private and isolated from all other clients.\n"
                            "You can upload, download, and manage your files securely here.\n"
                        )
                except Exception:
                    pass

            cursor.execute(
                """
                INSERT INTO users (fullname, email, username, password_hash, ftp_home_dir, is_active)
                VALUES (?, ?, ?, ?, ?, 1)
                """,
                (fullname, email, username, pw_hash, user_home_dir)
            )
            conn.commit()
            user_id = cursor.lastrowid

            user_data = {
                "id": user_id,
                "fullname": fullname,
                "email": email,
                "username": username,
                "ftp_home_dir": user_home_dir
            }
            return True, "Account created successfully! Your FTP account has been provisioned.", user_data

    except sqlite3.IntegrityError as e:
        return False, "An account with this username or email already exists.", None
    except Exception as e:
        return False, f"Failed to register user: {str(e)}", None


def authenticate_user(
    username_or_email: str,
    password: str,
    db_path: str = DEFAULT_DB_PATH
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Authenticates a user against the website user database using password hashes.
    Never stores or returns plaintext passwords.
    Returns (success, message, user_dict).
    """
    identifier = (username_or_email or "").strip().lower()
    password = password or ""

    if not identifier or not password:
        return False, "Please enter both username/email and password.", None

    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, fullname, email, username, password_hash, ftp_home_dir, is_active
                FROM users
                WHERE lower(username) = ? OR lower(email) = ?
                """,
                (identifier, identifier)
            )
            row = cursor.fetchone()

            if not row:
                return False, "Invalid username or password.", None

            if not row["is_active"]:
                return False, "Account has been deactivated. Please contact administrator.", None

            if not check_password_hash(row["password_hash"], password):
                return False, "Invalid username or password.", None

            user_data = {
                "id": row["id"],
                "fullname": row["fullname"],
                "email": row["email"],
                "username": row["username"],
                "ftp_home_dir": row["ftp_home_dir"]
            }
            return True, "Login successful.", user_data

    except Exception as e:
        return False, f"Authentication error: {str(e)}", None


def get_user_by_username(username: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieves a user record by username without password hash."""
    if not username:
        return None
    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, fullname, email, username, ftp_home_dir, is_active FROM users WHERE lower(username) = ?",
                (username.strip().lower(),)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
    except Exception:
        return None


def get_user_by_id(user_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieves a user record by ID without password hash."""
    if not user_id:
        return None
    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, fullname, email, username, ftp_home_dir, is_active FROM users WHERE id = ?",
                (user_id,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
    except Exception:
        return None
