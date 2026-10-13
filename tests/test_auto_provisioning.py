"""
test_auto_provisioning.py
Comprehensive automated test suite for NetTransfer:
1. Client registration (validation, secure password hashing, duplicate rejection)
2. Automatic FTP account provisioning (DatabaseAuthorizer without manual creation or restarts)
3. Client login & session management
4. Full file lifecycle (Upload, Download, Mkdir, Rename, Delete)
5. Multi-tenant directory isolation (User A vs User B)
6. Failed FTP connections, wrong credentials, and protected API authorization
Course: Computer Networks and Ethical Hacking
"""

import os
import sys
import time
import shutil
import tempfile
import threading
from ftplib import FTP, error_perm

# Add parent directory to path so project modules can be imported
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from database import (
    init_db,
    register_user,
    authenticate_user,
    get_user_by_username,
    get_db_connection
)
from run_demo_ftp_server import DatabaseAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from app import app


def run_tests():
    print("==================================================================")
    print("  NETTRANSFER - AUTOMATIC PROVISIONING & ISOLATION TEST SUITE")
    print("==================================================================")

    # Setup isolated temporary test environment
    test_dir = tempfile.mkdtemp(prefix="nettransfer_autotest_")
    test_db_path = os.path.join(test_dir, "test_users.db")
    test_storage_dir = os.path.join(test_dir, "test_storage")
    os.makedirs(test_storage_dir, exist_ok=True)

    # Initialize DB
    init_db(test_db_path)
    print(f"[*] Temporary Test Database : {test_db_path}")
    print(f"[*] Temporary Test Storage  : {test_storage_dir}")

    # Start an isolated test FTP server backed by DatabaseAuthorizer
    test_ftp_port = 2156
    authorizer = DatabaseAuthorizer(db_path=test_db_path, storage_root=test_storage_dir)
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.failed_login_delay = 0

    ftp_server = FTPServer(("127.0.0.1", test_ftp_port), handler)
    server_thread = threading.Thread(target=ftp_server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)
    print(f"[*] Test FTP Server running on 127.0.0.1:{test_ftp_port}\n")

    # Configure Flask test client
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    # Override app's database and storage paths
    import app as app_module
    app_module.DB_PATH = test_db_path
    app_module.STORAGE_PATH = test_storage_dir
    web_client = app.test_client()

    try:
        # =====================================================================
        # TEST 1: Client Registration & Input Validation
        # =====================================================================
        print("--- TEST 1: Client Registration & Validation ---")

        # 1a. Password too short
        ok, msg, _ = register_user(
            "Alice Short", "alice@example.com", "alice_short", "short", "short",
            db_path=test_db_path, storage_root=test_storage_dir
        )
        assert not ok and "at least 8" in msg.lower(), f"Expected short password rejection, got: {msg}"
        print("[PASS] Rejected password shorter than 8 characters.")

        # 1b. Password missing numbers
        ok, msg, _ = register_user(
            "Alice Nonum", "alice@example.com", "alice_nonum", "passwordonly", "passwordonly",
            db_path=test_db_path, storage_root=test_storage_dir
        )
        assert not ok and "both letters and numbers" in msg.lower(), f"Expected missing number rejection, got: {msg}"
        print("[PASS] Rejected password without numbers.")

        # 1c. Password mismatch
        ok, msg, _ = register_user(
            "Alice Mismatch", "alice@example.com", "alice_mismatch", "Pass1234", "Pass9999",
            db_path=test_db_path, storage_root=test_storage_dir
        )
        assert not ok and "do not match" in msg.lower(), f"Expected password mismatch, got: {msg}"
        print("[PASS] Rejected mismatched password confirmation.")

        # 1d. Invalid email
        ok, msg, _ = register_user(
            "Alice BadEmail", "invalid-email-address", "alice_bademail", "Pass1234", "Pass1234",
            db_path=test_db_path, storage_root=test_storage_dir
        )
        assert not ok and "valid email" in msg.lower(), f"Expected invalid email rejection, got: {msg}"
        print("[PASS] Rejected invalid email address.")

        # 1e. Successful Registration for Alice
        ok, msg, alice_data = register_user(
            "Alice Johnson", "alice@student.edu", "alice_j", "AlicePass123", "AlicePass123",
            db_path=test_db_path, storage_root=test_storage_dir
        )
        assert ok, f"Registration failed: {msg}"
        assert alice_data['username'] == "alice_j"
        print("[PASS] Registered client 'alice_j' successfully.")

        # Verify password is not in plaintext in SQLite
        with get_db_connection(test_db_path) as conn:
            row = conn.execute("SELECT password_hash FROM users WHERE username = 'alice_j'").fetchone()
            assert row is not None
            assert not row['password_hash'].startswith("AlicePass123"), "Password stored as plaintext!"
            assert "scrypt" in row['password_hash'] or "pbkdf2" in row['password_hash']
        print("[PASS] Password verified to be securely hashed (scrypt/PBKDF2).")

        # 1f. Duplicate registration rejected
        ok, msg, _ = register_user(
            "Alice Duplicate", "alice@student.edu", "alice_j", "AlicePass123", "AlicePass123",
            db_path=test_db_path, storage_root=test_storage_dir
        )
        assert not ok and "already" in msg.lower(), f"Expected duplicate rejection, got: {msg}"
        print("[PASS] Rejected duplicate registration with existing username/email.\n")

        # =====================================================================
        # TEST 2: Automatic FTP Server Account Provisioning
        # =====================================================================
        print("--- TEST 2: Automatic FTP Server Account Provisioning ---")
        # Notice: The FTP server was ALREADY running before alice_j registered!
        # DatabaseAuthorizer must recognize alice_j without any server restart or manual action!
        ftp = FTP()
        ftp.connect("127.0.0.1", test_ftp_port, timeout=5)
        login_res = ftp.login("alice_j", "AlicePass123")
        assert "230" in login_res, f"FTP login failed: {login_res}"
        print("[PASS] Server dynamically authenticated new client 'alice_j' via DatabaseAuthorizer without server restart.")

        # Verify client is restricted to own home directory
        current_pwd = ftp.pwd()
        assert current_pwd == "/", f"Expected root / for chrooted user, got {current_pwd}"
        file_list = ftp.nlst()
        assert "welcome.txt" in file_list, f"Expected initial welcome.txt, got {file_list}"
        print(f"[PASS] Client chrooted to isolated storage. Directory contents: {file_list}")
        ftp.quit()
        print()

        # =====================================================================
        # TEST 3: Web Login & Session Management
        # =====================================================================
        print("--- TEST 3: Web Login & Session Management ---")
        # 3a. Login with wrong password
        res = web_client.post('/api/login', json={'username': 'alice_j', 'password': 'WrongPassword123'})
        assert res.status_code == 401
        print("[PASS] Rejected login with incorrect password.")

        # 3b. Login with correct password
        res = web_client.post('/api/login', json={'username': 'alice_j', 'password': 'AlicePass123'})
        assert res.status_code == 200
        data = res.get_json()
        assert data['success'] and data['user']['username'] == 'alice_j'
        print("[PASS] Logged in successfully via /api/login.")

        # 3c. Query /api/me
        res = web_client.get('/api/me')
        assert res.status_code == 200
        me_data = res.get_json()
        assert me_data['authenticated'] and me_data['user']['username'] == 'alice_j'
        print("[PASS] Authenticated session confirmed via /api/me.\n")

        # =====================================================================
        # TEST 4: Full File Transfer Lifecycle
        # =====================================================================
        print("--- TEST 4: Full File Transfer Operations (Connect, Mkdir, Rename, Upload, Download, Delete) ---")
        # 4a. Connect via Web API
        res = web_client.post('/api/connect', json={
            'protocol': 'ftp',
            'host': '127.0.0.1',
            'port': test_ftp_port,
            'username': 'alice_j',
            'password': 'AlicePass123'
        })
        assert res.status_code == 200, f"Connect API failed: {res.get_json()}"
        print("[PASS] Connected to FTP storage via /api/connect.")

        # 4b. Create Folder
        res = web_client.post('/api/mkdir', json={'folder_name': 'course_notes'})
        assert res.status_code == 200
        print("[PASS] Created remote directory 'course_notes'.")

        # 4c. Rename Folder
        res = web_client.post('/api/rename', json={
            'old_name': 'course_notes',
            'new_name': 'cneh_project_docs',
            'type': 'directory'
        })
        assert res.status_code == 200
        print("[PASS] Renamed directory 'course_notes' -> 'cneh_project_docs'.")

        # 4d. Upload File
        sample_content = b"This is Alice's secure file uploaded via NetTransfer."
        res = web_client.post('/api/upload', data={
            'file': (tempfile.NamedTemporaryFile(), 'alice_notes.txt')
        }, content_type='multipart/form-data')
        # Re-upload with actual buffer
        import io
        res = web_client.post('/api/upload', data={
            'file': (io.BytesIO(sample_content), 'alice_notes.txt')
        }, content_type='multipart/form-data')
        assert res.status_code == 200
        print("[PASS] Uploaded file 'alice_notes.txt'.")

        # 4e. Rename File
        res = web_client.post('/api/rename', json={
            'old_name': 'alice_notes.txt',
            'new_name': 'alice_final_notes.txt',
            'type': 'file'
        })
        assert res.status_code == 200
        print("[PASS] Renamed file 'alice_notes.txt' -> 'alice_final_notes.txt'.")

        # 4f. Download File
        res = web_client.get('/api/download?filename=alice_final_notes.txt')
        assert res.status_code == 200
        assert res.data == sample_content, f"Content mismatch: {res.data}"
        print("[PASS] Downloaded and verified bit-for-bit file content.")

        # 4g. Delete File & Directory
        res = web_client.post('/api/delete', json={'name': 'alice_final_notes.txt', 'type': 'file'})
        assert res.status_code == 200
        res = web_client.post('/api/delete', json={'name': 'cneh_project_docs', 'type': 'directory'})
        assert res.status_code == 200
        print("[PASS] Deleted file and directory cleanly.")

        # Disconnect Alice
        web_client.post('/api/disconnect')
        web_client.post('/api/logout')
        print("[PASS] Disconnected and logged out Alice.\n")

        # =====================================================================
        # TEST 5: Multi-Tenant Client Isolation (User A vs User B)
        # =====================================================================
        print("--- TEST 5: Multi-Tenant Client Isolation ---")
        # Alice creates a confidential file
        alice_storage = os.path.join(test_storage_dir, "users", "alice_j")
        with open(os.path.join(alice_storage, "alice_confidential.txt"), "w") as f:
            f.write("CONFIDENTIAL: Alice Private Exam Notes")

        # Register Bob
        ok, msg, bob_data = register_user(
            "Bob Smith", "bob@student.edu", "bob_s", "BobSecret987", "BobSecret987",
            db_path=test_db_path, storage_root=test_storage_dir
        )
        assert ok
        print("[PASS] Registered client 'bob_s'.")

        # Bob logs in and connects via FTP
        ftp_bob = FTP()
        ftp_bob.connect("127.0.0.1", test_ftp_port, timeout=5)
        ftp_bob.login("bob_s", "BobSecret987")

        bob_files = ftp_bob.nlst()
        assert "welcome.txt" in bob_files
        assert "alice_confidential.txt" not in bob_files, "CRITICAL: Bob can see Alice's files!"
        print(f"[PASS] Bob's storage is isolated. Bob files: {bob_files} (Alice's file is invisible).")

        # Attempt directory traversal from Bob's session to reach Alice's files
        traversal_failed = False
        try:
            ftp_bob.cwd("../alice_j")
        except error_perm:
            traversal_failed = True
        # In pyftpdlib abstracted fs, cwd('..') stays in root or raises error
        assert ftp_bob.pwd() == "/" or traversal_failed, "Bob escaped chroot!"
        assert "alice_confidential.txt" not in ftp_bob.nlst(), "Bob accessed Alice's directory!"
        print("[PASS] Chroot prevents Bob from navigating into Alice's directory.")
        ftp_bob.quit()
        print()

        # =====================================================================
        # TEST 6: Error Handling & API Authorization Protection
        # =====================================================================
        print("--- TEST 6: Error Handling & API Authorization Protection ---")
        # 6a. Attempt FTP connection with wrong password
        try:
            ftp_fail = FTP()
            ftp_fail.connect("127.0.0.1", test_ftp_port, timeout=5)
            ftp_fail.login("alice_j", "WrongPassword")
            assert False, "Login should have been rejected!"
        except error_perm as e:
            assert "530" in str(e)
            print("[PASS] FTP server rejected invalid credentials with RFC 530 Login incorrect.")

        # 6b. Attempt FTP connection with non-existent user
        try:
            ftp_ghost = FTP()
            ftp_ghost.connect("127.0.0.1", test_ftp_port, timeout=5)
            ftp_ghost.login("ghost_unknown_user", "AnyPassword123")
            assert False, "Unknown user should have been rejected!"
        except error_perm as e:
            assert "530" in str(e)
            print("[PASS] FTP server rejected non-existent user with RFC 530.")

        # 6c. Protected Web API requires login
        guest_client = app.test_client()
        res = guest_client.get('/api/files')
        assert res.status_code == 401, f"Expected 401 Unauthorized for guest, got {res.status_code}"
        print("[PASS] Protected endpoint /api/files rejected unauthenticated guest with 401.")

        res = guest_client.post('/api/connect', json={'host': '127.0.0.1'})
        assert res.status_code == 401
        print("[PASS] Protected endpoint /api/connect rejected unauthenticated guest with 401.")

        print("\n==================================================================")
        print("  ALL 6 AUTOMATIC PROVISIONING & ISOLATION TEST SUITES PASSED!   ")
        print("==================================================================")

    finally:
        # Stop test FTP server
        try:
            ftp_server.close_all()
        except Exception:
            pass
        # Clean up temporary test files
        try:
            shutil.rmtree(test_dir, ignore_errors=True)
        except Exception:
            pass


if __name__ == "__main__":
    run_tests()
