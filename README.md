# NetTransfer – FTP File Transfer System
### Course: Computer Networks and Ethical Hacking
**Project Title:** Implementation of Application Layer Protocols  
**Protocol Focus:** File Transfer Protocol (FTP – RFC 959)

---

## 1. Project Overview

**NetTransfer** is a lightweight, web-based FTP client built for the Computer Networks and Ethical Hacking course project. The system demonstrates the practical implementation and operation of **Application Layer protocols** over TCP/IP networks.

Using standard RFC 959 specifications, the application communicates with an FTP server via a dual-connection model:
1. **Control Connection (TCP Port 21 / Custom Port):** Stays open for the duration of the session to exchange ASCII commands (`USER`, `PASS`, `PWD`, `CWD`, `CDUP`, `LIST`/`MLSD`, `STOR`, `RETR`, `DELE`, `QUIT`) and 3-digit numerical response codes (`220`, `230`, `250`, `150`, `226`, `530`, `550`).
2. **Data Connection (Passive Mode `PASV`):** Dynamically opens ephemeral data sockets for transferring directory listings and binary file payloads safely through NAT routers and client firewalls.

The user interface is designed with a modern, clean **blue-and-white** aesthetic that is responsive across laptops, tablets, and mobile screens.

---

## 2. Technologies Used

- **Frontend:**
  - **HTML5:** Semantic card-based structure.
  - **CSS3:** Custom responsive layout, high-contrast typography, and status badges (no heavy CSS frameworks).
  - **JavaScript (Vanilla ES6):** Asynchronous API communication using `fetch()`, dynamic DOM rendering, and real-time activity logging.
- **Backend:**
  - **Python 3:** Application logic and networking.
  - **Flask:** Lightweight WSGI web framework providing REST API endpoints.
  - **Python `ftplib`:** Python's standard library implementation of the FTP protocol.
  - **Python `tempfile`:** Temporary file storage for downloads with immediate post-response cleanup.
- **Local Test Server:**
  - **`pyftpdlib`:** Configurable local FTP server enabling safe, isolated offline testing and lab evaluations.

---

## 3. Project Folder Structure

```
CNEH project/
│
├── app.py                      # Flask backend providing REST endpoints
├── ftp_service.py              # Modular FTP client wrapper using ftplib
├── run_demo_ftp_server.py      # Configurable local authorized test FTP server
├── requirements.txt            # Python dependencies (Flask, pyftpdlib)
├── run.bat                     # Windows batch launcher (starts server & opens browser)
├── README.md                   # Complete documentation and setup manual
│
├── static/
│   ├── css/
│   │   └── style.css           # Blue-and-white responsive stylesheet
│   └── js/
│       └── app.js              # Client-side controller and activity logger
│
├── templates/
│   └── index.html              # Main single-page web interface
│
└── tests/
    ├── test_ftp_integration.py # Automated end-to-end integration test suite
    └── smoke_test.py           # Live HTTP server and browser network test
```

---

## 4. Installation Steps

### Prerequisites
- Python 3.10 or higher (Verified with Python 3.12)
- Any standard web browser (Chrome, Edge, Firefox)

### Step 1: Open Terminal in Project Directory
Navigate to the project directory:
```bash
cd "c:\Users\Dell\OneDrive\Desktop\24071A67M3\CNEH project"
```

### Step 2: Install Required Dependencies
Install the required packages using `pip`:
```bash
pip install -r requirements.txt
```

---

## 5. How to Run the Website

### Option A: Running in Visual Studio Code (VS Code)

1. **Open Folder in VS Code:**
   - Launch VS Code, click **File > Open Folder...**, and select the `CNEH project` folder.
2. **Select Python Interpreter:**
   - Press `Ctrl + Shift + P`, type `Python: Select Interpreter`, and choose your installed Python 3 interpreter.
3. **Open Integrated Terminal:**
   - Press `Ctrl + ~` (or select **Terminal > New Terminal**).
4. **Start the Test FTP Server:**
   In Terminal 1:
   ```bash
   python run_demo_ftp_server.py
   ```
5. **Start the Flask Web App:**
   Click the `+` button in the terminal panel to open Terminal 2:
   ```bash
   python app.py
   ```
6. **Access the Website:**
   Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

### Option B: Windows One-Click Launcher

Double-click `run.bat` in the project directory. The script will automatically:
1. Start the authorized test FTP server in the background.
2. Start the Flask application.
3. Open your default web browser directly to `http://127.0.0.1:5000`.

---

## 6. How to Configure and Connect to a Test FTP Server

> **Security Note:** NetTransfer does not hardcode credentials. You connect to an FTP server you own or are authorized to access. Passwords are used strictly in-memory and are never stored on disk or displayed in logs.

### Setting Up Your Authorized Local Test Server
You can launch the included test server with custom credentials using command-line arguments:

```bash
python run_demo_ftp_server.py --port 2121 --user myuser --password mysecretpass
```

Alternatively, you can set environment variables:
```powershell
$env:FTP_PORT = "2121"
$env:FTP_USER = "student"
$env:FTP_PASS = "student123"
python run_demo_ftp_server.py
```

*Default test server credentials if no flags are passed:*
- **Host:** `127.0.0.1`
- **Port:** `2121`
- **Username:** `student`
- **Password:** `student123`

### Connecting via the NetTransfer Interface
1. In the **FTP Connection Settings** card:
   - Click **"Autofill Local Host (127.0.0.1:2121)"** or enter your custom FTP server IP and port.
   - Enter your **Username** and **Password**.
2. Click **Connect**.
3. The badge will switch from **Disconnected** to **Connected** (Green) and the **Activity Log** will display the successful connection event.

---

## 7. How to Test Upload and Download

Once connected:

### Testing File Listing and Directory Navigation
1. The **File Manager** table automatically displays the real files located in the FTP server's working directory.
2. Click on any folder (e.g., `lab_documents`) or click its **Open** button to navigate into it (`CWD` command).
3. Click the **Parent Folder (..)** button to navigate back to the parent directory (`CDUP` command).

### Testing File Download
1. Locate any file in the table (e.g., `welcome.txt` or `cneh_project_overview.txt`).
2. Click the **Download** button.
3. The file will be transferred from the remote server via the `RETR` command and downloaded directly to your browser's Downloads folder.

### Testing File Upload
1. Click the **Upload File** button in the File Manager toolbar.
2. Select any local file from your computer (e.g., a `.txt` or `.pdf` file).
3. The system will upload the file to the current remote directory using the `STOR` command.
4. The file list refreshes automatically, displaying your newly uploaded file and its size.

### Testing Disconnect
1. Click the red **Disconnect** button.
2. The FTP control connection sends `QUIT` and closes the socket.
3. The interface returns to the disconnected state and the file list resets.

---

## 8. Known Limitations

1. **Plaintext FTP Protocol (RFC 959):** Standard FTP transmits control commands in cleartext over the wire. In untrusted production networks, FTPS (FTP over TLS) or SFTP (SSH File Transfer Protocol) should be used instead.
2. **Directory Deletion:** In standard FTP implementations (via RFC 959 `RMD`), a directory can only be deleted if it is already empty.
3. **Session Persistence across Restarts:** For security, FTP connections and session tokens exist purely in memory; restarting the Flask server gracefully terminates active connections.
4. **Maximum Upload Size:** A safety limit of 50 MB is enforced on file uploads to protect demonstration servers from resource exhaustion.

---

## 9. Verification & Automated Testing

To run the automated integration tests:
```bash
python tests/test_ftp_integration.py
```

To run the live HTTP smoke test:
```bash
python tests/smoke_test.py
```
Both test suites verify:
- Valid and invalid login authentication.
- Error handling for refused connections and wrong credentials.
- Bit-for-bit accuracy of file upload and download operations.
- Path traversal sanitization preventing arbitrary directory access.
- Temporary file download cleanup and password privacy.
