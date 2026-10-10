"""
run_demo_ftp_server.py
Configurable Local Demo FTP Server for testing and lab presentation.
Uses pyftpdlib to host an authorized local FTP test server.
Course: Computer Networks and Ethical Hacking
"""

import os
import sys
import argparse
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

def setup_demo_directory(root_dir):
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
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    ftp_root = os.path.join(base_dir, "demo_ftp_storage")
    setup_demo_directory(ftp_root)

    authorizer = DummyAuthorizer()

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
    print("      NETTRANSFER - AUTHORIZED TEST FTP SERVER (RFC 959)")
    print("==================================================================")
    print(f"[*] Root Directory    : {ftp_root}")
    print(f"[*] Server Address    : {args.host}:{args.port}")
    print(f"[*] Configured User   : {args.user}")
    print("==================================================================")
    print("[*] You can configure credentials via:")
    print("    python run_demo_ftp_server.py --user <name> --password <pass> --port <port>")
    print("    Or set environment variables: FTP_USER, FTP_PASS, FTP_PORT")
    print("==================================================================")
    print("[*] Press Ctrl+C in this terminal to stop the server.")
    print("==================================================================")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Test FTP Server stopped.")

if __name__ == "__main__":
    main()
