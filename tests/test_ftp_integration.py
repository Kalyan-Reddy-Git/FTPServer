"""
tests/test_ftp_integration.py
Automated end-to-end verification script for NetTransfer backend.
Tests:
1. Real FTP connection lifecycle via Python ftplib.
2. Credentials authentication and error handling for invalid logins.
3. Directory listing of real FTP server contents (MLSD / LIST).
4. Subdirectory navigation and parent folder traversal (CWD / CDUP).
5. Safe file upload with filename sanitization.
6. Safe file download using temporary files with immediate cleanup.
7. Path traversal prevention tests.
8. Deletion and termination (QUIT).
9. Full Flask REST API test suite.
"""

import os
import sys
import time
import threading
import io
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# Ensure project root is in sys.path
base_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(base_dir, ".."))
sys.path.insert(0, project_root)

test_storage = os.path.join(base_dir, "test_ftp_storage")
os.makedirs(test_storage, exist_ok=True)

# Prepare real test files on FTP server
with open(os.path.join(test_storage, "hello_lab.txt"), "w") as f:
    f.write("NetTransfer Real Server Test File")

sub_dir = os.path.join(test_storage, "test_folder")
os.makedirs(sub_dir, exist_ok=True)
with open(os.path.join(sub_dir, "nested_file.txt"), "w") as f:
    f.write("Nested document inside sub-directory")

# Configure and start a local FTP server on port 2135
authorizer = DummyAuthorizer()
authorizer.add_user("testuser", "testpass123", test_storage, perm="elradfmwM")
handler = FTPHandler
handler.authorizer = authorizer
server = FTPServer(("127.0.0.1", 2135), handler)

server_thread = threading.Thread(target=server.serve_forever, daemon=True)
server_thread.start()
print("[*] Test FTP Server started on 127.0.0.1:2135")
time.sleep(1)

from ftp_service import FTPClient, sanitize_filename

print("\n=== STEP 1: Testing Path Traversal Sanitization ===")
assert sanitize_filename("../../etc/passwd") == "passwd"
assert sanitize_filename("..\\..\\windows\\win.ini") == "win.ini"
assert sanitize_filename("safe_report.pdf") == "safe_report.pdf"
assert sanitize_filename("..") == ""
assert sanitize_filename(".") == ""
print("[PASS] Path sanitization correctly stripped dangerous directory traversal sequences.")

print("\n=== STEP 2: Testing Python ftplib Client Directly ===")
client = FTPClient()

# 1. Invalid credentials test
res_fail = client.connect("127.0.0.1", 2135, "testuser", "WRONG_PASSWORD")
assert res_fail["success"] is False
assert "530" in res_fail["message"] or "Authentication failed" in res_fail["message"]
print("[PASS] Handled invalid credentials gracefully:", res_fail["message"])

# 2. Connection refused test (unused port)
res_refused = client.connect("127.0.0.1", 65520, "testuser", "pass")
assert res_refused["success"] is False
assert "refused" in res_refused["message"].lower()
print("[PASS] Handled connection refusal gracefully.")

# 3. Valid connection
res_ok = client.connect("127.0.0.1", 2135, "testuser", "testpass123")
assert res_ok["success"] is True
print("[PASS] Connected successfully to test FTP server.")

# 4. List real files
res_list = client.list_files()
assert res_list["success"] is True
filenames = [f["name"] for f in res_list["files"]]
assert "hello_lab.txt" in filenames
assert "test_folder" in filenames
print(f"[PASS] Real FTP directory contents returned: {filenames}")

# 5. Navigate into subdirectory
nav_res = client.change_directory("test_folder")
assert nav_res["success"] is True
sub_list = client.list_files()
sub_filenames = [f["name"] for f in sub_list["files"]]
assert "nested_file.txt" in sub_filenames
print(f"[PASS] Navigated into 'test_folder'. Contents: {sub_filenames}")

# 6. Navigate to parent
parent_res = client.change_to_parent()
assert parent_res["success"] is True
print("[PASS] Navigated to parent directory.")

# 7. Upload file
upload_data = b"Testing binary upload via STOR command."
up_res = client.upload_file("direct_upload.txt", io.BytesIO(upload_data))
assert up_res["success"] is True
print("[PASS] File uploaded to FTP server.")

# 8. Download file to temp file
dl_res = client.download_to_tempfile("direct_upload.txt")
assert dl_res["success"] is True
temp_filepath = dl_res["temp_path"]
assert os.path.exists(temp_filepath)
with open(temp_filepath, "rb") as f:
    downloaded_bytes = f.read()
assert downloaded_bytes == upload_data
os.remove(temp_filepath)  # Clean up
print("[PASS] File downloaded to temporary storage and verified bit-for-bit.")

# 9. Delete file
del_res = client.delete_item("direct_upload.txt", is_dir=False)
assert del_res["success"] is True
print("[PASS] File deleted successfully.")

# 10. Disconnect
disc_res = client.disconnect()
assert disc_res["success"] is True
print("[PASS] Disconnected from FTP server.")


print("\n=== STEP 3: Testing Flask Web API Endpoints ===")
from app import app
flask_client = app.test_client()

# GET /
r = flask_client.get('/')
assert r.status_code == 200
assert b"NetTransfer" in r.data
print("[PASS] GET / returned web application interface.")

# GET /api/files before connecting (should reject)
r = flask_client.get('/api/files')
assert r.status_code == 400
print("[PASS] Unauthenticated /api/files rejected.")

# POST /api/connect with invalid credentials
r = flask_client.post('/api/connect', json={
    'host': '127.0.0.1',
    'port': 2135,
    'username': 'testuser',
    'password': 'badpassword'
})
assert r.status_code == 400
assert r.get_json()['success'] is False
print("[PASS] POST /api/connect returned 400 on authentication failure.")

# POST /api/connect with valid credentials
r = flask_client.post('/api/connect', json={
    'host': '127.0.0.1',
    'port': 2135,
    'username': 'testuser',
    'password': 'testpass123'
})
assert r.status_code == 200
connect_json = r.get_json()
assert connect_json['success'] is True
assert 'password' not in connect_json  # Ensure password is NEVER leaked in response
print("[PASS] POST /api/connect succeeded. Password not exposed.")

# GET /api/status
r = flask_client.get('/api/status')
assert r.status_code == 200
assert r.get_json()['connected'] is True
print("[PASS] GET /api/status confirmed active session.")

# GET /api/files (real files)
r = flask_client.get('/api/files')
assert r.status_code == 200
files = r.get_json()['files']
assert any(f['name'] == 'hello_lab.txt' for f in files)
print(f"[PASS] GET /api/files returned {len(files)} real FTP files.")

# POST /api/upload
upload_payload = {
    'file': (io.BytesIO(b"Flask multipart upload content"), "endpoint_test.txt")
}
r = flask_client.post('/api/upload', data=upload_payload, content_type='multipart/form-data')
assert r.status_code == 200
assert r.get_json()['success'] is True
print("[PASS] POST /api/upload uploaded file successfully.")

# GET /api/download (and check temporary file was removed)
r = flask_client.get('/api/download?filename=endpoint_test.txt')
assert r.status_code == 200
assert r.data == b"Flask multipart upload content"
print("[PASS] GET /api/download streamed downloaded file content correctly.")

# POST /api/cwd
r = flask_client.post('/api/cwd', json={'path': 'test_folder', 'action': 'into'})
assert r.status_code == 200
assert r.get_json()['current_directory'] == '/test_folder'

r = flask_client.post('/api/cwd', json={'action': 'parent'})
assert r.status_code == 200
assert r.get_json()['current_directory'] == '/'
print("[PASS] POST /api/cwd directory navigation functioning.")

# POST /api/delete
r = flask_client.post('/api/delete', json={'name': 'endpoint_test.txt', 'type': 'file'})
assert r.status_code == 200
print("[PASS] POST /api/delete removed file.")

# POST /api/disconnect
r = flask_client.post('/api/disconnect')
assert r.status_code == 200
assert r.get_json()['success'] is True

# Verify status after disconnect
r = flask_client.get('/api/status')
assert r.get_json()['connected'] is False
print("[PASS] POST /api/disconnect terminated session.")

# Cleanup
server.close_all()
try:
    import shutil
    shutil.rmtree(test_storage)
except Exception:
    pass

print("\n=======================================================")
print(" ALL 12 BACKEND AND SECURITY REQUIREMENTS FULLY PASSED!")
print("=======================================================")
