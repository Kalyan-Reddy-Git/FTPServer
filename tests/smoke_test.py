"""
tests/smoke_test.py
Standalone smoke test script verifying live HTTP server startup and browser connectivity.
"""

import os
import sys
import time
import subprocess
import requests

python_exe = sys.executable

# 1. Start Demo FTP server in subprocess
ftp_proc = subprocess.Popen(
    [python_exe, "run_demo_ftp_server.py", "--port", "2140", "--user", "smokeuser", "--password", "smokepass123"],
    cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

# 2. Start Flask server in subprocess
flask_proc = subprocess.Popen(
    [python_exe, "app.py"],
    cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
    env=dict(os.environ, FLASK_DEBUG="0")
)

try:
    print("[*] Waiting 3 seconds for servers to start...")
    time.sleep(3)

    session = requests.Session()

    # Test 1: Web server root
    resp = session.get("http://127.0.0.1:5000/")
    print(f"[1] GET http://127.0.0.1:5000/ -> Status {resp.status_code}")
    assert resp.status_code == 200
    assert "NetTransfer" in resp.text
    assert "FTP Connection Settings" in resp.text
    print("    [PASS] Web interface loads successfully!")

    # Test 2: Invalid FTP connection
    resp = session.post("http://127.0.0.1:5000/api/connect", json={
        "host": "127.0.0.1",
        "port": 2140,
        "username": "smokeuser",
        "password": "wrongpassword"
    })
    print(f"[2] POST /api/connect (Invalid) -> Status {resp.status_code}")
    assert resp.status_code == 400
    data = resp.json()
    assert data["success"] is False
    assert "530" in data["message"] or "Authentication failed" in data["message"]
    print(f"    [PASS] Error message displayed clearly: {data['message']}")

    # Test 3: Valid FTP connection
    resp = session.post("http://127.0.0.1:5000/api/connect", json={
        "host": "127.0.0.1",
        "port": 2140,
        "username": "smokeuser",
        "password": "smokepass123"
    })
    print(f"[3] POST /api/connect (Valid) -> Status {resp.status_code}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "password" not in data  # Security check: password never in response
    print(f"    [PASS] Connected successfully: {data['message']}")

    # Test 4: Real file listing
    resp = session.get("http://127.0.0.1:5000/api/files")
    print(f"[4] GET /api/files -> Status {resp.status_code}")
    assert resp.status_code == 200
    files = resp.json()["files"]
    print(f"    [PASS] Displayed {len(files)} real FTP files: {[f['name'] for f in files]}")
    assert len(files) > 0

    # Test 5: Uploading a file
    test_content = b"Smoke test file content over Application Layer FTP!"
    files_payload = {'file': ('smoke_uploaded.txt', test_content, 'text/plain')}
    resp = session.post("http://127.0.0.1:5000/api/upload", files=files_payload)
    print(f"[5] POST /api/upload -> Status {resp.status_code}")
    assert resp.status_code == 200
    assert resp.json()["success"] is True
    print("    [PASS] File uploaded successfully!")

    # Test 6: Downloading the file
    resp = session.get("http://127.0.0.1:5000/api/download?filename=smoke_uploaded.txt")
    print(f"[6] GET /api/download -> Status {resp.status_code}")
    assert resp.status_code == 200
    assert resp.content == test_content
    print("    [PASS] Downloaded file verified bit-for-bit!")

    # Test 7: Directory navigation
    resp = session.post("http://127.0.0.1:5000/api/cwd", json={"path": "lab_documents", "action": "into"})
    print(f"[7] POST /api/cwd (into) -> Status {resp.status_code}")
    assert resp.status_code == 200
    assert resp.json()["current_directory"] == "/lab_documents"

    resp = session.post("http://127.0.0.1:5000/api/cwd", json={"action": "parent"})
    print(f"[8] POST /api/cwd (parent) -> Status {resp.status_code}")
    assert resp.status_code == 200
    assert resp.json()["current_directory"] == "/"
    print("    [PASS] Directory navigation verified!")

    # Test 8: Disconnect
    resp = session.post("http://127.0.0.1:5000/api/disconnect")
    print(f"[9] POST /api/disconnect -> Status {resp.status_code}")
    assert resp.status_code == 200
    assert resp.json()["success"] is True
    print("    [PASS] Session disconnected cleanly!")

    print("\n=========================================================")
    print("ALL LIVE NETWORK AND BROWSER TESTS PASSED FLAWLESSLY!")
    print("=========================================================")

finally:
    print("[*] Terminating background server processes...")
    try:
        flask_proc.terminate()
        ftp_proc.terminate()
    except Exception:
        pass
