"""
tests/test_multi_protocol.py
Automated test suite verifying multi-protocol features (FTP, FTPS, SFTP),
connection test endpoint, directory creation, item renaming, upload/download,
path sanitization, and SSRF filtering.
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

test_storage = os.path.join(base_dir, "test_multi_proto_storage")
os.makedirs(test_storage, exist_ok=True)

# Create an initial test file
with open(os.path.join(test_storage, "sample.txt"), "w") as f:
    f.write("NetTransfer Multi-Protocol Test File")

# Start an isolated local FTP test server on port 2145
authorizer = DummyAuthorizer()
authorizer.add_user("testuser", "testpass123", test_storage, perm="elradfmwM")
handler = FTPHandler
handler.authorizer = authorizer
handler.failed_login_delay = 0
server = FTPServer(("127.0.0.1", 2145), handler)

server_thread = threading.Thread(target=server.serve_forever, daemon=True)
server_thread.start()
print("[*] Local Test FTP Server started on 127.0.0.1:2145")
time.sleep(1)

from ftp_service import (
    validate_host,
    sanitize_filename,
    FTPClient,
    FTPSClient,
    SFTPClient,
    create_client_instance
)

print("\n--- TEST 1: SSRF Filtering & Path Sanitization ---")
is_valid, err = validate_host("169.254.169.254")
assert not is_valid, "Failed to block AWS metadata IP"
print("[PASS] Blocked SSRF cloud metadata endpoint (169.254.169.254)")

is_valid, err = validate_host("metadata.google.internal")
assert not is_valid, "Failed to block GCP metadata hostname"
print("[PASS] Blocked GCP metadata hostname")

is_valid, err = validate_host("127.0.0.1")
assert is_valid, "Valid IP was falsely rejected"
print("[PASS] Allowed valid test host 127.0.0.1")

assert sanitize_filename("../../../etc/shadow") == "shadow"
assert sanitize_filename("..\\..\\boot.ini") == "boot.ini"
assert sanitize_filename("..") == ""
print("[PASS] Path sanitization neutralized directory traversal sequences")

print("\n--- TEST 2: Factory & Multi-Protocol Client Classes ---")
client_ftp = create_client_instance("ftp")
assert isinstance(client_ftp, FTPClient)
assert client_ftp.protocol == "ftp"

client_ftps = create_client_instance("ftps")
assert isinstance(client_ftps, FTPSClient)
assert client_ftps.protocol == "ftps"

client_sftp = create_client_instance("sftp")
assert isinstance(client_sftp, SFTPClient)
assert client_sftp.protocol == "sftp"
print("[PASS] Factory successfully created FTP, FTPS, and SFTP client instances")

print("\n--- TEST 3: Test Connection API Endpoint ---")
from app import app
flask_client = app.test_client()

# Test connection with wrong credentials (should fail gracefully)
r = flask_client.post('/api/test-connect', json={
    'host': '127.0.0.1',
    'port': 2145,
    'username': 'testuser',
    'password': 'WRONG_PASSWORD',
    'protocol': 'ftp'
})
assert r.status_code == 400
assert r.get_json()['success'] is False
print("[PASS] Test connection correctly rejected bad credentials:", r.get_json()['message'])

# Test connection with valid credentials (should succeed)
r = flask_client.post('/api/test-connect', json={
    'host': '127.0.0.1',
    'port': 2145,
    'username': 'testuser',
    'password': 'testpass123',
    'protocol': 'ftp'
})
assert r.status_code == 200
assert r.get_json()['success'] is True
print("[PASS] Test connection succeeded:", r.get_json()['message'])

print("\n--- TEST 4: Full File Lifecycle (Connect, List, Mkdir, Rename, Upload, Download, Delete) ---")
# 1. Connect
r = flask_client.post('/api/connect', json={
    'host': '127.0.0.1',
    'port': 2145,
    'username': 'testuser',
    'password': 'testpass123',
    'protocol': 'ftp'
})
assert r.status_code == 200
assert r.get_json()['success'] is True
print("[PASS] Connected to server via FTP")

# 2. Status
r = flask_client.get('/api/status')
assert r.status_code == 200
status_data = r.get_json()
assert status_data['connected'] is True
assert status_data['protocol'] == 'ftp'
print("[PASS] Status verified: Protocol =", status_data['protocol'])

# 3. Create folder
r = flask_client.post('/api/mkdir', json={'folder_name': 'project_docs'})
assert r.status_code == 200
assert r.get_json()['success'] is True
filenames = [f['name'] for f in r.get_json()['files']]
assert 'project_docs' in filenames
print("[PASS] Created directory 'project_docs'")

# 4. Rename folder
r = flask_client.post('/api/rename', json={
    'old_name': 'project_docs',
    'new_name': 'archived_docs',
    'type': 'directory'
})
assert r.status_code == 200
assert r.get_json()['success'] is True
filenames = [f['name'] for f in r.get_json()['files']]
assert 'archived_docs' in filenames
assert 'project_docs' not in filenames
print("[PASS] Renamed directory 'project_docs' -> 'archived_docs'")

# 5. Upload file
upload_payload = {
    'file': (io.BytesIO(b"Dynamic upload content for NetTransfer"), "dynamic_file.txt")
}
r = flask_client.post('/api/upload', data=upload_payload, content_type='multipart/form-data')
assert r.status_code == 200
assert r.get_json()['success'] is True
print("[PASS] Uploaded file 'dynamic_file.txt'")

# 6. Rename file
r = flask_client.post('/api/rename', json={
    'old_name': 'dynamic_file.txt',
    'new_name': 'renamed_dynamic.txt',
    'type': 'file'
})
assert r.status_code == 200
assert r.get_json()['success'] is True
print("[PASS] Renamed file 'dynamic_file.txt' -> 'renamed_dynamic.txt'")

# 7. Download file
r = flask_client.get('/api/download?filename=renamed_dynamic.txt')
assert r.status_code == 200
assert r.data == b"Dynamic upload content for NetTransfer"
print("[PASS] Downloaded and verified content of 'renamed_dynamic.txt'")

# 8. Delete file and folder
r = flask_client.post('/api/delete', json={'name': 'renamed_dynamic.txt', 'type': 'file'})
assert r.status_code == 200

r = flask_client.post('/api/delete', json={'name': 'archived_docs', 'type': 'directory'})
assert r.status_code == 200
print("[PASS] Deleted file and folder successfully")

# 9. Disconnect
r = flask_client.post('/api/disconnect')
assert r.status_code == 200
assert r.get_json()['success'] is True
print("[PASS] Disconnected session cleanly")

# Clean up
server.close_all()
try:
    import shutil
    shutil.rmtree(test_storage)
except Exception:
    pass

print("\n=======================================================")
print(" ALL MULTI-PROTOCOL AND ADVANCED OPERATION TESTS PASSED!")
print("=======================================================")
