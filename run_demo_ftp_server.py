"""
run_demo_ftp_server.py
Configurable Local Demo FTP Server with Dynamic Database Provisioning.
Uses pyftpdlib backed by SQLite and Werkzeug password hashing.
Course: Computer Networks and Ethical Hacking
"""

import os
import sys
import argparse
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from werkzeug.security import check_password_hash

from database import (
    init_db,
    get_db_connection,
    DEFAULT_DB_PATH,
    DEFAULT_STORAGE_PATH
)


class DatabaseAuthorizer(DummyAuthorizer):
    """
    Authorizer that dynamically authenticates registered website users against SQLite.
    Automatically assigns and chroots each client into their isolated home directory.
    Passwords are never stored in plaintext — verified dynamically using secure hashes.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH, storage_root: str = DEFAULT_STORAGE_PATH):
        super().__init__()
        self.db_path = db_path
        self.storage_root = storage_root

    def add_user(self, username: str, password: str, homedir: str, perm: str = "elr", msg_login: str = "", msg_quit: str = ""):
        """Safely registers or updates a user without raising ValueError if already present in DB."""
        self.user_table[username] = {
            'pwd': password,
            'home': homedir,
            'perm': perm,
            'operms': {},
            'msg_login': msg_login,
            'msg_quit': msg_quit
        }

    def has_user(self, username: str) -> bool:
        if super().has_user(username):
            return True
        try:
            with get_db_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id FROM users WHERE lower(username) = ? AND is_active = 1",
                    (username.strip().lower(),)
                )
                return cursor.fetchone() is not None
        except Exception:
            return False

    def validate_authentication(self, username: str, password: str, handler) -> None:
        username = (username or "").strip()
        # 1. Pre-configured static users (e.g. student, demo) in memory
        if username in self.user_table and self.user_table[username]['pwd']:
            return super().validate_authentication(username, password, handler)

        # 2. Dynamic database lookup for registered clients
        try:
            with get_db_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT username, password_hash, ftp_home_dir, is_active FROM users WHERE lower(username) = ?",
                    (username.lower(),)
                )
                row = cursor.fetchone()

                if not row:
                    raise AuthenticationFailed("Authentication failed (User not found).")

                if not row['is_active']:
                    raise AuthenticationFailed("Account is deactivated.")

                # Verify password against secure scrypt / pbkdf2 hash
                if not check_password_hash(row['password_hash'], password):
                    raise AuthenticationFailed("Authentication failed (Incorrect password).")

                actual_username = row['username']
                user_home = row['ftp_home_dir']

                if not os.path.isabs(user_home):
                    user_home = os.path.join(self.storage_root, "users", actual_username)

                # Ensure user's isolated home directory exists
                os.makedirs(user_home, exist_ok=True)

                # Dynamically configure session in user_table
                user_entry = {
                    'pwd': '',  # Plaintext password is NEVER retained in memory
                    'home': user_home,
                    'perm': 'elradfmwM',  # Full read/write/delete permissions inside own directory
                    'operms': {},
                    'msg_login': f'Welcome to your private NetTransfer storage, {actual_username}.',
                    'msg_quit': 'Session terminated.'
                }
                self.user_table[actual_username] = user_entry
                if username != actual_username:
                    self.user_table[username] = user_entry

                return None

        except AuthenticationFailed:
            raise
        except Exception as e:
            raise AuthenticationFailed(f"Authentication error: {str(e)}")

    def get_home_dir(self, username: str) -> str:
        if username in self.user_table:
            return self.user_table[username]['home']
        try:
            with get_db_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT ftp_home_dir FROM users WHERE lower(username) = ?",
                    (username.strip().lower(),)
                )
                row = cursor.fetchone()
                if row:
                    return row['ftp_home_dir']
        except Exception:
            pass
        return super().get_home_dir(username)

    def get_perms(self, username: str) -> str:
        if username in self.user_table:
            return self.user_table[username]['perm']
        return "elradfmwM"

    def has_perm(self, username: str, perm: str, path: str = None) -> bool:
        if username in self.user_table:
            return perm in self.user_table[username]['perm']
        return True


def setup_demo_directory(root_dir: str):
    """Creates sample files and folders for testing FTP operations."""
    os.makedirs(root_dir, exist_ok=True)

    file1 = os.path.join(root_dir, "welcome.txt")
    if not os.path.exists(file1):
        with open(file1, "w", encoding="utf-8") as f:
            f.write(
                "Welcome to NetTransfer Demo FTP Server!\n"
                "----------------------------------------\n"
                "This FTP server is running locally to demonstrate Application Layer Protocols.\n"
                "Protocol: FTP (File Transfer Protocol - RFC 959)\n"
                "Feel free to download this file, upload new files, or navigate folders.\n"
            )

    file2 = os.path.join(root_dir, "cneh_project_overview.txt")
    if not os.path.exists(file2):
        with open(file2, "w", encoding="utf-8") as f:
            f.write(
                "Project Title: Implementation of Application Layer Protocols\n"
                "Course: Computer Networks and Ethical Hacking Laboratory\n"
                "System: NetTransfer Web FTP Client\n"
                "Technologies: Python ftplib, Flask, HTML, CSS, JavaScript\n"
            )

    sub_dir = os.path.join(root_dir, "lab_documents")
    os.makedirs(sub_dir, exist_ok=True)

    sub_file = os.path.join(sub_dir, "experiment_manual.txt")
    if not os.path.exists(sub_file):
        with open(sub_file, "w", encoding="utf-8") as f:
            f.write(
                "Experiment No: Application Layer FTP Client Implementation\n"
                "Objective: Understand control vs data connections in FTP and implement\n"
                "file retrieval and storage using socket-based ftplib.\n"
            )


def main():
    parser = argparse.ArgumentParser(description="NetTransfer Authorized Local Test FTP Server")
    parser.add_argument("--host", default=os.environ.get("FTP_HOST", "127.0.0.1"), help="Host IP to bind to")
    parser.add_argument("--port", type=int, default=int(os.environ.get("FTP_PORT", 2121)), help="Port to listen on")
    parser.add_argument("--user", default=os.environ.get("FTP_USER", "student"), help="Authorized test username")
    parser.add_argument("--password", default=os.environ.get("FTP_PASS", "student123"), help="Authorized test password")
    parser.add_argument("--allow-anonymous", action="store_true", default=True, help="Enable anonymous read-only access")
    parser.add_argument("--db-path", default=DEFAULT_DB_PATH, help="Path to SQLite user database")
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    ftp_root = os.path.join(base_dir, "demo_ftp_storage")
    setup_demo_directory(ftp_root)

    # Initialize SQLite database
    init_db(args.db_path)

    # Use our custom DatabaseAuthorizer
    authorizer = DatabaseAuthorizer(db_path=args.db_path, storage_root=ftp_root)

    # Pre-register common test accounts with full read/write/delete permissions
    authorizer.add_user("student", "student123", ftp_root, perm="elradfmwM")
    authorizer.add_user("demo", "password123", ftp_root, perm="elradfmwM")

    # Add custom user if specified via CLI or environment variable
    if args.user not in ["student", "demo"]:
        authorizer.add_user(args.user, args.password, ftp_root, perm="elradfmwM")

    # Add anonymous user if allowed
    if args.allow_anonymous:
        authorizer.add_anonymous(ftp_root, perm="elr")

    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = "NetTransfer Authorized Test FTP Server Ready (RFC 959)."
    # Prevent sleep delay on invalid authentication for fast UI feedback
    handler.failed_login_delay = 0

    server = FTPServer((args.host, args.port), handler)
    server.max_cons = 256
    server.max_cons_per_ip = 10

    print("==================================================================")
    print("      NETTRANSFER - DYNAMIC MULTI-TENANT TEST FTP SERVER")
    print("==================================================================")
    print(f"[*] Root Directory    : {ftp_root}")
    print(f"[*] Server Address    : {args.host}:{args.port}")
    print(f"[*] User Database     : {args.db_path}")
    print(f"[*] Provisioning Mode : Dynamic Database-Backed (Automatic)")
    print(f"[*] Pre-loaded Users  : student, demo, {args.user}")
    print("==================================================================")
    print("[*] New clients registered via website are automatically authenticated")
    print("    and chrooted into their isolated private home directory.")
    print("==================================================================")
    print("[*] Press Ctrl+C in this terminal to stop the server.")
    print("==================================================================")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Test FTP Server stopped.")


if __name__ == "__main__":
    main()
