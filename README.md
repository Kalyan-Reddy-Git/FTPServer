# NetTransfer – Multi-Protocol File Transfer System
### Course: Computer Networks and Ethical Hacking (CNEH)
**Project Title:** Implementation of Application Layer Protocols  
**Protocols Implemented:**
- **FTP** (File Transfer Protocol – RFC 959)
- **FTPS** (FTP over TLS/SSL – RFC 4217)
- **SFTP** (SSH File Transfer Protocol – SSH-2.0 via Paramiko)

---

## 1. Project Overview

**NetTransfer** is a modern, web-based file transfer client engineered for the Computer Networks and Ethical Hacking course project. The application demonstrates the design, security, and operation of **Application Layer file transfer protocols** over TCP/IP networks.

Rather than relying on hardcoded credentials or mock data, NetTransfer provides a fully dynamic, multi-protocol interface allowing users to connect to any authorized FTP, FTPS, or SFTP server.

### Protocol Architecture:
1. **FTP (Plain RFC 959):**
   - **Control Connection (TCP Port 21 / Custom):** Exchanges commands (`USER`, `PASS`, `PWD`, `CWD`, `MKD`, `RNFR`, `RNTO`, `DELE`, `QUIT`) and receives standard response codes (`220`, `230`, `250`, `150`, `226`, `530`, `550`).
   - **Data Connection (Passive Mode `PASV`):** Dynamically opens ephemeral data sockets for transferring directory listings and file payloads.
   - *Security Note:* Control commands and credentials travel in cleartext over the wire.
2. **FTPS (FTP over Explicit TLS – RFC 4217):**
   - Establishes a standard FTP socket on Port 21, then upgrades the channel to TLS/SSL using `AUTH TLS`. Both the control channel and data channel (`PROT P`) are encrypted to protect passwords and payload in transit.
3. **SFTP (SSH File Transfer Protocol – Port 22):**
   - Operates over an encrypted SSH-2.0 transport channel (`paramiko`), multiplexing control commands and file streaming over a single secure port.

The user interface maintains a clean **blue-and-white** college project aesthetic that is responsive across laptops, tablets, and mobile devices.

---

## 2. Key Features

- **Client Registration & Automatic FTP Account Provisioning:**
  - Client enters Full Name, Email, Username, Password, and Confirm Password.
  - Secure `scrypt`/PBKDF2 password hashing — plaintext passwords are never stored or logged.
  - Automatic backend provisioning: Creates isolated client storage (`users/<username>`) and links credentials directly with the FTP server.
  - Zero manual admin account creation needed — `DatabaseAuthorizer` authenticates clients dynamically without server restarts.
  - Multi-tenant directory chroot isolation: Each client is restricted strictly to their own directory.
- **Dynamic Connection Settings:**
  - Selectable Protocol: **FTP**, **FTPS**, or **SFTP**.
  - Customizable Hostname / IP address, Port, Username, and Password.
  - Auto-updating default port (FTP/FTPS: 21, SFTP: 22).
  - Protocol security advisory alert explaining cleartext risks for FTP vs encrypted FTPS/SFTP.
- **Connection Controls:**
  - **Test Connection Button:** Validates host reachability and credentials non-destructively without switching session state.
  - **Connect & Disconnect:** Clean socket initialization and graceful session teardown.
  - **Live Status Indicator:** Real-time visual badge showing connection state, host, user, and protocol.
- **Real File Management Operations:**
  - **Real Directory Listing:** Renders live server directory contents with file/folder icons, human-readable sizes, and timestamps.
  - **Directory Navigation:** Drill into folders (`CWD`) and return to parent folders (`CDUP` / `..`).
  - **File Upload with Live Progress:** Real-time percentage progress bar and byte transfer indicator.
  - **File Download:** Streams files securely from the remote server with automatic server-side temporary file cleanup immediately after transfer.
  - **Create New Folder (`mkdir`):** Modal dialog to create new remote directories.
  - **Rename Files & Folders (`rename`):** In-place renaming via `RNFR`/`RNTO` (FTP) or `posix_rename` (SFTP).
  - **Delete Items:** Safely remove files and empty directories with confirmation dialogs.
- **Security & Ethical Hacking Safeguards:**
  - **Protected Private APIs:** All file operations require an active authenticated web session via `@login_required`.
  - **In-Memory Password Handling:** Credentials are never written to disk, never printed to console logs, and never returned in API payloads or client-side storage.
  - **SSRF (Server-Side Request Forgery) Defense:** Validates target hostnames to block attacks targeting cloud metadata endpoints (`169.254.169.254`, AWS, GCP, Azure metadata services).
  - **Path Traversal Protection:** Filenames are sanitized with strict character sets and traversal stripping (`../`, `..\`) before executing server filesystem commands.
  - **Multi-User Session Isolation:** Each browser session receives an isolated transfer client instance with automatic 15-minute idle expiration.

---

## 3. Technologies Used

- **Frontend:**
  - **HTML5:** Semantic card-based interface with modal dialogs.
  - **CSS3:** Custom responsive styling with clean blue-and-white visual identity (no bulky third-party UI libraries).
  - **JavaScript (Vanilla ES6):** Asynchronous API integration via `fetch` and `XMLHttpRequest` (for upload progress tracking), DOM rendering, and real-time activity logging.
- **Backend:**
  - **Python 3.12 / 3.10+:** Application runtime.
  - **Flask:** Lightweight REST API microframework.
  - **Python `ftplib`:** Standard library FTP and FTPS (Explicit TLS) client engine.
  - **Paramiko (SSH/SFTP):** Python implementation of the SSHv2 protocol providing SFTP client communication.
  - **Gunicorn:** Production WSGI HTTP server for Render deployment.
  - **`tempfile`:** Isolated temporary download spooling with Flask `@after_this_request` hook for instant garbage collection.
- **Local Test Server:**
  - **`pyftpdlib`:** RFC 959 compliant test FTP server for safe, isolated offline demonstrations and grading.

---

## 4. Project Folder Structure

```
CNEH project/
│
├── app.py                      # Flask backend providing REST endpoints
├── ftp_service.py              # Multi-protocol transfer engine (FTP, FTPS, SFTP)
├── run_demo_ftp_server.py      # Configurable local authorized test FTP server
├── requirements.txt            # Python dependencies (Flask, pyftpdlib, paramiko, gunicorn)
├── Procfile                    # Render WSGI deployment command
├── render.yaml                 # Render Infrastructure as Code configuration
├── run.bat                     # Windows one-click launcher
├── README.md                   # Full documentation manual
│
├── static/
│   ├── css/
│   │   └── style.css           # Blue-and-white responsive stylesheet
│   └── js/
│       └── app.js              # Client-side controller, modal handlers, and logger
│
├── templates/
│   └── index.html              # Main single-page web interface
│
└── tests/
    ├── test_multi_protocol.py  # Multi-protocol, SSRF, path traversal, & file lifecycle test
    ├── test_ftp_integration.py # Automated end-to-end integration test suite
    └── smoke_test.py           # Live HTTP server and browser network test
```

---

## 5. Installation & Local Setup

### Prerequisites
- Python 3.10 or higher (Tested on Python 3.12)
- Any modern web browser (Google Chrome, Microsoft Edge, Mozilla Firefox)

### Step 1: Open Terminal in Project Directory
```bash
cd "c:\Users\Dell\OneDrive\Desktop\24071A67M3\CNEH project"
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 6. How to Run Locally

### Option A: Running with Terminal / VS Code

1. **Terminal 1 – Start the Test FTP Server:**
   ```bash
   python run_demo_ftp_server.py --port 2121
   ```
   *Default test server credentials:*
   - Host: `127.0.0.1`
   - Port: `2121`
   - Username: `student`
   - Password: `student123`

2. **Terminal 2 – Start the Web Application:**
   ```bash
   python app.py
   ```

3. **Open the Web Browser:**
   Navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

### Option B: Windows One-Click Launcher (`run.bat`)

Double-click `run.bat` in the project root directory. It will:
1. Start the authorized local test FTP server.
2. Start the Flask application.
3. Automatically launch your default browser to `http://127.0.0.1:5000`.

---

## 7. How to Use the Application

### 1. Test Connection Before Connecting
1. In the **Connection Settings** card, select your protocol (**FTP**, **FTPS**, or **SFTP**).
2. Enter the **Host / IP**, **Port**, **Username**, and **Password** (or click **Autofill Local Host** for the test server).
3. Click **Test Connection**.
4. The system validates whether the server is reachable and credentials are valid without altering your active session.

### 2. Connect
1. Click **Connect**.
2. The badge switches to **Connected** (Green), showing the active protocol and host.
3. The **File Manager** automatically populates with the real remote directory listing.

### 3. File & Directory Operations
- **Navigate Folders:** Click on any directory row or click its **Open** button. Click **Parent Folder (..)** to return to the parent directory.
- **Create Folder:** Click **+ New Folder**, enter the folder name, and confirm.
- **Upload File:** Click **Upload File**, choose a local file. The upload progress bar tracks real-time progress.
- **Rename Item:** Click the **Rename** button next to any file or folder, enter the new name, and submit.
- **Download File:** Click the **Download** button. The file will be transferred and saved to your local machine.
- **Delete Item:** Click the **Delete** button and confirm in the modal dialog.

### 4. Disconnect
- Click **Disconnect** to close all open sockets and clear your session state.

---

## 8. Deploying to Render

This project is configured for one-click deployment on [Render](https://render.com):

1. **Push your code to GitHub:**
   Ensure your changes are committed and pushed to your GitHub repository (e.g., `https://github.com/Kalyan-Reddy-Git/FTPServer`).

2. **Create a Web Service on Render:**
   - Log in to your Render dashboard and click **New + > Web Service**.
   - Connect your GitHub repository `Kalyan-Reddy-Git/FTPServer`.
   - Settings:
     - **Environment:** `Python 3`
     - **Build Command:** `pip install -r requirements.txt`
     - **Start Command:** `gunicorn app:app`
   - Alternatively, Render will automatically detect `render.yaml` and `Procfile`.

3. **Deploy & Access:**
   - Click **Deploy Web Service**.
   - Once deployed, your web application will be accessible at your public Render URL (e.g., `https://ftpserver-xxxx.onrender.com`).
   - You can connect to any publicly reachable FTP, FTPS, or SFTP server directly from the web interface.

---

## 9. Automated Verification & Test Suite

Run the comprehensive multi-protocol test suite:
```bash
python tests/test_multi_protocol.py
```

Run the standard FTP integration suite:
```bash
python tests/test_ftp_integration.py
```

Run the live HTTP smoke test:
```bash
python tests/smoke_test.py
```

All tests verify:
- SSRF filtering against cloud metadata IP addresses and endpoints.
- Path traversal sanitization preventing arbitrary directory escapes.
- Protocol factory instantiation (FTP, FTPS, SFTP).
- Non-destructive `Test Connection` behavior.
- Full file lifecycle: `mkdir`, `rename`, `upload`, `download`, and `delete`.
- Clean socket disconnection and session cleanup.

---

## 10. Known Limitations & Security Considerations

1. **Unencrypted FTP Cleartext Risk:** Plain FTP (RFC 959) transmits commands and passwords in cleartext. NetTransfer displays a clear security advisory whenever FTP is selected. For production use, FTPS or SFTP should always be chosen.
2. **SFTP Host Key Verification:** In demo/lab mode, the SFTP client accepts unknown host keys (`AutoAddPolicy`) for ease of demonstration. In high-security production environments, strict `known_hosts` verification should be enforced.
3. **Empty Directory Removal:** RFC 959 (`RMD`) requires directories to be empty before deletion.
4. **Maximum Upload Size:** A default 50 MB limit is configured to avoid memory/disk exhaustion on free-tier hosting platforms.
