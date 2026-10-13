"""
ftp_service.py
Multi-protocol transfer client supporting FTP, FTPS, and SFTP.
Course: Computer Networks and Ethical Hacking
Project: NetTransfer - Implementation of Application Layer Protocols

PROTOCOLS SUPPORTED:
- FTP (Plain RFC 959) via Python standard library `ftplib.FTP`
- FTPS (FTP over TLS - RFC 4217) via Python standard library `ftplib.FTP_TLS`
- SFTP (SSH File Transfer Protocol) via `paramiko.SFTPClient`

SECURITY FEATURES:
- Session isolation (no cross-user connection leaks)
- Passwords kept strictly in-memory (never logged or persisted)
- Path traversal defense on uploads, downloads, folder creation, and renaming
- SSRF filtering against cloud metadata endpoints and invalid hosts
- Automatic cleanup of idle sessions (15-minute timeout)
"""

import os
import re
import time
import socket
import ssl
import stat
import tempfile
import posixpath
from ftplib import FTP, FTP_TLS, error_perm, error_temp, error_proto

# Try importing paramiko for SFTP support
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# Maximum idle timeout for an inactive session (15 minutes)
SESSION_IDLE_TIMEOUT_SECONDS = 900

# Blocked SSRF targets (Cloud metadata endpoints and invalid addresses)
BLOCKED_SSRF_HOSTS = {
    "169.254.169.254",          # AWS / OpenStack / Azure metadata
    "metadata.google.internal", # GCP metadata
    "100.100.100.200",          # Alibaba Cloud metadata
    "instance-data",            # AWS legacy alias
    "255.255.255.255",          # Broadcast
    "0.0.0.0"                   # Unspecified
}


def validate_host(host):
    """
    Validates the host string and guards against SSRF attacks.
    Returns (is_valid: bool, error_message: str or None).
    """
    if not host or not isinstance(host, str):
        return False, "Host cannot be empty."

    cleaned_host = host.strip()
    if not cleaned_host:
        return False, "Host cannot be blank."

    # Check for blocked metadata IP addresses
    if cleaned_host.lower() in BLOCKED_SSRF_HOSTS:
        return False, f"Access to restricted infrastructure host '{cleaned_host}' is blocked for security."

    # Disallow control characters, whitespace, and path traversal in hostname
    if re.search(r"[\s/\\]", cleaned_host):
        return False, "Hostname contains invalid characters or whitespace."

    return True, None


def sanitize_filename(filename):
    """
    Sanitizes filename and prevents directory traversal attacks.
    Ensures filename is strictly a single filename with no path separators.
    """
    if not filename or not isinstance(filename, str):
        return ""
    # Strip any directory path components (both UNIX / and Windows \)
    clean_name = os.path.basename(filename.replace("\\", "/")).strip()
    # Remove null bytes and control characters
    clean_name = re.sub(r"[\x00-\x1f\x7f]", "", clean_name)
    # Disallow relative navigation names
    if clean_name in [".", ".."]:
        return ""
    return clean_name


class BaseTransferClient:
    """Abstract base class establishing the unified API across FTP, FTPS, and SFTP."""

    def __init__(self, protocol="ftp"):
        self.protocol = protocol
        self.host = None
        self.port = 21
        self.username = None
        self.connected = False
        self.last_activity = time.time()

    def connect(self, host, port, username, password):
        raise NotImplementedError

    def test_connection(self, host, port, username, password):
        raise NotImplementedError

    def is_alive(self):
        raise NotImplementedError

    def get_current_directory(self):
        raise NotImplementedError

    def list_files(self):
        raise NotImplementedError

    def change_directory(self, target_folder):
        raise NotImplementedError

    def change_to_parent(self):
        raise NotImplementedError

    def create_directory(self, folder_name):
        raise NotImplementedError

    def rename_item(self, old_name, new_name):
        raise NotImplementedError

    def upload_file(self, filename, file_stream):
        raise NotImplementedError

    def download_to_tempfile(self, filename):
        raise NotImplementedError

    def delete_item(self, item_name, is_dir=False):
        raise NotImplementedError

    def disconnect(self):
        raise NotImplementedError


# ==============================================================================
# 1. FTP CLIENT (Standard RFC 959)
# ==============================================================================
class FTPClient(BaseTransferClient):
    """Handles standard, unencrypted File Transfer Protocol connections."""

    def __init__(self):
        super().__init__(protocol="ftp")
        self.ftp = None

    def connect(self, host, port=21, username="anonymous", password=""):
        self.disconnect()

        is_valid, err = validate_host(host)
        if not is_valid:
            return {"success": False, "message": err}

        self.host = host.strip()
        if self.host.lower() == "localhost":
            self.host = "127.0.0.1"
        try:
            self.port = int(port)
            if self.port < 1 or self.port > 65535:
                self.port = 21
        except (ValueError, TypeError):
            self.port = 21

        self.username = username.strip() if username else "anonymous"
        auth_password = password if password else ""

        try:
            self.ftp = FTP(timeout=10)
            welcome_msg = self.ftp.connect(self.host, self.port, timeout=10)
            login_msg = self.ftp.login(self.username, auth_password)
            self.ftp.set_pasv(True)
            self.connected = True
            self.last_activity = time.time()

            return {
                "success": True,
                "message": f"Connected to {self.host}:{self.port} via FTP as '{self.username}'.",
                "welcome": welcome_msg,
                "protocol": "ftp",
                "current_directory": self.get_current_directory()
            }

        except ConnectionRefusedError:
            self.connected = False
            return {
                "success": False,
                "message": f"Connection refused at {self.host}:{self.port}. Ensure the FTP server is running and the port is correct."
            }
        except (socket.timeout, TimeoutError):
            self.connected = False
            return {
                "success": False,
                "message": f"Connection timed out reaching {self.host}:{self.port}. Check firewall or network settings."
            }
        except socket.gaierror:
            self.connected = False
            return {
                "success": False,
                "message": f"Could not resolve hostname '{self.host}'. Check server address."
            }
        except error_perm as e:
            self.connected = False
            err_text = str(e)
            if "530" in err_text:
                return {
                    "success": False,
                    "message": "Authentication failed (530 Login incorrect). Please check your username and password."
                }
            return {"success": False, "message": f"FTP Permission Error: {err_text}"}
        except Exception as e:
            self.connected = False
            return {"success": False, "message": f"FTP Connection error: {str(e)}"}

    def test_connection(self, host, port=21, username="anonymous", password=""):
        """Performs a test connection handshake and disconnects immediately."""
        is_valid, err = validate_host(host)
        if not is_valid:
            return {"success": False, "message": err}

        test_ftp = None
        target_host = host.strip()
        if target_host.lower() == "localhost":
            target_host = "127.0.0.1"
        try:
            port_num = int(port)
            test_ftp = FTP(timeout=8)
            test_ftp.connect(target_host, port_num, timeout=8)
            test_ftp.login(username.strip() if username else "anonymous", password if password else "")
            test_ftp.voidcmd("NOOP")
            test_ftp.quit()
            return {
                "success": True,
                "message": f"FTP connection test succeeded! Server reachable at {target_host}:{port_num} with provided credentials.",
                "protocol": "ftp"
            }
        except error_perm as e:
            if "530" in str(e):
                return {"success": False, "message": "FTP server reachable, but credentials failed (530 Login incorrect)."}
            return {"success": False, "message": f"FTP server permission error: {str(e)}"}
        except ConnectionRefusedError:
            return {"success": False, "message": f"Connection refused at {host}:{port}. Check if FTP server is running."}
        except (socket.timeout, TimeoutError):
            return {"success": False, "message": f"Connection test timed out reaching {host}:{port}."}
        except Exception as e:
            return {"success": False, "message": f"Connection test failed: {str(e)}"}
        finally:
            if test_ftp:
                try:
                    test_ftp.close()
                except Exception:
                    pass

    def is_alive(self):
        if not self.ftp or not self.connected:
            return False
        try:
            self.ftp.voidcmd("NOOP")
            return True
        except Exception:
            self.connected = False
            return False

    def get_current_directory(self):
        if not self.connected or not self.ftp:
            return "/"
        try:
            return self.ftp.pwd()
        except Exception:
            return "/"

    def list_files(self):
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected.", "files": []}

        try:
            current_dir = self.get_current_directory()
            items = []
            supports_mlsd = True

            try:
                for name, facts in self.ftp.mlsd():
                    if name in [".", ".."]:
                        continue
                    item_type = facts.get("type", "file").lower()
                    size = int(facts.get("size", 0)) if "size" in facts else 0
                    modify = facts.get("modify", "")
                    items.append({
                        "name": name,
                        "type": "directory" if item_type in ["dir", "cdir", "pdir"] else "file",
                        "size": size,
                        "modified": modify
                    })
            except (error_perm, error_proto, AttributeError):
                supports_mlsd = False

            if not supports_mlsd:
                items = self._fallback_list()

            items.sort(key=lambda x: (0 if x["type"] == "directory" else 1, x["name"].lower()))
            self.last_activity = time.time()
            return {"success": True, "current_directory": current_dir, "files": items}

        except error_perm as e:
            return {"success": False, "message": f"Permission denied reading directory: {str(e)}", "files": []}
        except Exception as e:
            return {"success": False, "message": f"Failed to list directory contents: {str(e)}", "files": []}

    def _fallback_list(self):
        lines = []
        try:
            self.ftp.retrlines("LIST", lines.append)
        except Exception:
            try:
                names = self.ftp.nlst()
                return [{"name": n, "type": "file", "size": 0, "modified": ""} for n in names if n not in [".", ".."]]
            except Exception:
                return []

        items = []
        for line in lines:
            line_clean = line.strip()
            if not line_clean:
                continue
            parts = line_clean.split(maxsplit=8)
            if len(parts) >= 9:
                perms = parts[0]
                is_dir = perms.startswith("d")
                try:
                    size = int(parts[4])
                except ValueError:
                    size = 0
                name = parts[8].strip()
                if name in [".", ".."]:
                    continue
                items.append({
                    "name": name,
                    "type": "directory" if is_dir else "file",
                    "size": size,
                    "modified": " ".join(parts[5:8])
                })
            else:
                name = line_clean
                if name and name not in [".", ".."]:
                    items.append({"name": name, "type": "file", "size": 0, "modified": ""})
        return items

    def change_directory(self, target_folder):
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected."}
        clean_folder = sanitize_filename(target_folder)
        if not clean_folder:
            return {"success": False, "message": "Invalid directory name specified."}

        try:
            res = self.ftp.cwd(clean_folder)
            self.last_activity = time.time()
            return {"success": True, "message": f"Directory changed to '{clean_folder}'.", "current_directory": self.get_current_directory()}
        except error_perm as e:
            return {"success": False, "message": f"Cannot access directory '{clean_folder}': {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Directory navigation error: {str(e)}"}

    def change_to_parent(self):
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected."}
        try:
            try:
                self.ftp.cwd("..")
            except Exception:
                self.ftp.voidcmd("CDUP")
            self.last_activity = time.time()
            return {"success": True, "message": "Navigated to parent directory.", "current_directory": self.get_current_directory()}
        except error_perm as e:
            return {"success": False, "message": f"Already at root directory or permission denied: {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Error navigating up: {str(e)}"}

    def create_directory(self, folder_name):
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected."}
        clean_name = sanitize_filename(folder_name)
        if not clean_name:
            return {"success": False, "message": "Invalid folder name specified."}

        try:
            res = self.ftp.mkd(clean_name)
            self.last_activity = time.time()
            return {"success": True, "message": f"Directory '{clean_name}' created successfully."}
        except error_perm as e:
            return {"success": False, "message": f"Failed to create directory (550 Permission/Exists): {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Error creating directory '{clean_name}': {str(e)}"}

    def rename_item(self, old_name, new_name):
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected."}
        clean_old = sanitize_filename(old_name)
        clean_new = sanitize_filename(new_name)
        if not clean_old or not clean_new:
            return {"success": False, "message": "Invalid filename specified for rename."}

        try:
            self.ftp.rename(clean_old, clean_new)
            self.last_activity = time.time()
            return {"success": True, "message": f"Successfully renamed '{clean_old}' to '{clean_new}'."}
        except error_perm as e:
            return {"success": False, "message": f"Rename failed (Permission denied or target exists): {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Error renaming item: {str(e)}"}

    def upload_file(self, filename, file_stream):
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected."}
        clean_name = sanitize_filename(filename)
        if not clean_name:
            return {"success": False, "message": "Invalid filename for upload."}

        try:
            file_stream.seek(0)
            self.ftp.storbinary(f"STOR {clean_name}", file_stream)
            self.last_activity = time.time()
            return {"success": True, "message": f"Successfully uploaded '{clean_name}' via FTP."}
        except error_perm as e:
            return {"success": False, "message": f"Upload permission denied by FTP server (550): {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Failed to upload '{clean_name}': {str(e)}"}

    def download_to_tempfile(self, filename):
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected.", "temp_path": None}
        clean_name = sanitize_filename(filename)
        if not clean_name:
            return {"success": False, "message": "Invalid filename for download.", "temp_path": None}

        temp_file = None
        try:
            temp_file = tempfile.NamedTemporaryFile(delete=False, prefix="nettransfer_dl_")
            temp_path = temp_file.name

            self.ftp.retrbinary(f"RETR {clean_name}", temp_file.write)
            temp_file.flush()
            temp_file.close()

            self.last_activity = time.time()
            return {"success": True, "message": f"Successfully retrieved '{clean_name}'.", "temp_path": temp_path, "clean_filename": clean_name}
        except error_perm as e:
            if temp_file and os.path.exists(temp_file.name):
                try:
                    os.remove(temp_file.name)
                except Exception:
                    pass
            return {"success": False, "message": f"Download failed (Permission/Not found): {str(e)}", "temp_path": None}
        except Exception as e:
            if temp_file and os.path.exists(temp_file.name):
                try:
                    os.remove(temp_file.name)
                except Exception:
                    pass
            return {"success": False, "message": f"Error downloading '{clean_name}': {str(e)}", "temp_path": None}

    def delete_item(self, item_name, is_dir=False):
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected."}
        clean_name = sanitize_filename(item_name)
        if not clean_name:
            return {"success": False, "message": "Invalid name specified for deletion."}

        try:
            if is_dir:
                self.ftp.rmd(clean_name)
                msg = f"Directory '{clean_name}' removed successfully."
            else:
                self.ftp.delete(clean_name)
                msg = f"File '{clean_name}' deleted successfully."
            self.last_activity = time.time()
            return {"success": True, "message": msg}
        except error_perm as e:
            return {"success": False, "message": f"Delete permission denied by FTP server: {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Failed to delete '{clean_name}': {str(e)}"}

    def disconnect(self):
        if self.ftp:
            try:
                self.ftp.quit()
            except Exception:
                try:
                    self.ftp.close()
                except Exception:
                    pass
            finally:
                self.ftp = None
        self.connected = False
        self.host = None
        self.username = None
        return {"success": True, "message": "Disconnected from FTP server."}


# ==============================================================================
# 2. FTPS CLIENT (FTP over TLS - RFC 4217)
# ==============================================================================
class FTPSClient(FTPClient):
    """Handles explicit FTPS (FTP over TLS) connections with protected data channel."""

    def __init__(self):
        super().__init__()
        self.protocol = "ftps"

    def connect(self, host, port=21, username="anonymous", password=""):
        self.disconnect()

        is_valid, err = validate_host(host)
        if not is_valid:
            return {"success": False, "message": err}

        self.host = host.strip()
        try:
            self.port = int(port)
            if self.port < 1 or self.port > 65535:
                self.port = 21
        except (ValueError, TypeError):
            self.port = 21

        self.username = username.strip() if username else "anonymous"
        auth_password = password if password else ""

        # Attempt connection with certificate verification, falling back for self-signed lab certificates
        for verify_cert in (True, False):
            try:
                ctx = ssl.create_default_context()
                if not verify_cert:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                self.ftp = FTP_TLS(context=ctx, timeout=10)
                welcome_msg = self.ftp.connect(self.host, self.port, timeout=10)
                self.ftp.auth()
                self.ftp.login(self.username, auth_password)
                self.ftp.prot_p()  # Secure the data connection with TLS
                self.ftp.set_pasv(True)

                self.connected = True
                self.last_activity = time.time()
                cert_note = " (Verified TLS)" if verify_cert else " (Self-signed TLS Certificate)"

                return {
                    "success": True,
                    "message": f"Connected to {self.host}:{self.port} via FTPS{cert_note} as '{self.username}'.",
                    "welcome": welcome_msg,
                    "protocol": "ftps",
                    "current_directory": self.get_current_directory()
                }

            except (ssl.SSLCertVerificationError, ssl.SSLError) as e:
                if verify_cert:
                    # Retry with unverified context for self-signed certificates common in academic environments
                    continue
                self.connected = False
                return {"success": False, "message": f"FTPS TLS Handshake error: {str(e)}"}
            except ConnectionRefusedError:
                self.connected = False
                return {"success": False, "message": f"Connection refused at {self.host}:{self.port}. Ensure FTPS server is running."}
            except (socket.timeout, TimeoutError):
                self.connected = False
                return {"success": False, "message": f"FTPS connection timed out reaching {self.host}:{self.port}."}
            except error_perm as e:
                self.connected = False
                if "530" in str(e):
                    return {"success": False, "message": "FTPS Authentication failed (530 Login incorrect). Check username and password."}
                return {"success": False, "message": f"FTPS Permission Error: {str(e)}"}
            except Exception as e:
                self.connected = False
                return {"success": False, "message": f"FTPS Connection error: {str(e)}"}

    def test_connection(self, host, port=21, username="anonymous", password=""):
        is_valid, err = validate_host(host)
        if not is_valid:
            return {"success": False, "message": err}

        for verify_cert in (True, False):
            test_ftp = None
            try:
                port_num = int(port)
                ctx = ssl.create_default_context()
                if not verify_cert:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                test_ftp = FTP_TLS(context=ctx, timeout=8)
                test_ftp.connect(host.strip(), port_num, timeout=8)
                test_ftp.auth()
                test_ftp.login(username.strip() if username else "anonymous", password if password else "")
                test_ftp.prot_p()
                test_ftp.voidcmd("NOOP")
                test_ftp.quit()
                cert_status = "Verified TLS" if verify_cert else "Self-Signed Certificate Accepted"
                return {
                    "success": True,
                    "message": f"FTPS connection test succeeded! Server reachable with encrypted TLS ({cert_status}).",
                    "protocol": "ftps"
                }
            except (ssl.SSLCertVerificationError, ssl.SSLError):
                if verify_cert:
                    continue
                return {"success": False, "message": "FTPS TLS Certificate validation failed."}
            except error_perm as e:
                if "530" in str(e):
                    return {"success": False, "message": "FTPS server reachable over TLS, but credentials rejected (530 Login incorrect)."}
                return {"success": False, "message": f"FTPS server error: {str(e)}"}
            except ConnectionRefusedError:
                return {"success": False, "message": f"Connection refused at {host}:{port}. Is the FTPS server active?"}
            except Exception as e:
                return {"success": False, "message": f"FTPS test connection failed: {str(e)}"}
            finally:
                if test_ftp:
                    try:
                        test_ftp.close()
                    except Exception:
                        pass


# ==============================================================================
# 3. SFTP CLIENT (SSH File Transfer Protocol via Paramiko)
# ==============================================================================
class SFTPClient(BaseTransferClient):
    """Handles SFTP (SSH File Transfer Protocol) connections over SSH Port 22."""

    def __init__(self):
        super().__init__(protocol="sftp")
        self.ssh = None
        self.sftp = None
        self.current_dir = "/"

    def connect(self, host, port=22, username="root", password=""):
        self.disconnect()

        if not PARAMIKO_AVAILABLE:
            return {"success": False, "message": "SFTP support requires 'paramiko'. Please ensure it is installed in requirements.txt."}

        is_valid, err = validate_host(host)
        if not is_valid:
            return {"success": False, "message": err}

        self.host = host.strip()
        try:
            self.port = int(port)
            if self.port < 1 or self.port > 65535:
                self.port = 22
        except (ValueError, TypeError):
            self.port = 22

        self.username = username.strip() if username else ""
        auth_password = password if password else ""

        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=auth_password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            self.sftp = self.ssh.open_sftp()
            self.connected = True
            self.last_activity = time.time()

            # Determine initial working directory
            try:
                self.current_dir = self.sftp.normalize(".")
            except Exception:
                self.current_dir = "/"

            return {
                "success": True,
                "message": f"Connected to {self.host}:{self.port} via SFTP (SSH-2.0) as '{self.username}'.",
                "protocol": "sftp",
                "current_directory": self.current_dir
            }

        except paramiko.AuthenticationException:
            self.connected = False
            return {"success": False, "message": "SFTP Authentication failed. Incorrect username or password."}
        except paramiko.SSHException as e:
            self.connected = False
            return {"success": False, "message": f"SSH/SFTP Protocol error: {str(e)}"}
        except ConnectionRefusedError:
            self.connected = False
            return {"success": False, "message": f"SSH connection refused at {self.host}:{self.port}. Ensure SSH/SFTP server is running on port {self.port}."}
        except (socket.timeout, TimeoutError):
            self.connected = False
            return {"success": False, "message": f"SFTP connection timed out reaching {self.host}:{self.port}."}
        except Exception as e:
            self.connected = False
            return {"success": False, "message": f"SFTP connection error: {str(e)}"}

    def test_connection(self, host, port=22, username="", password=""):
        if not PARAMIKO_AVAILABLE:
            return {"success": False, "message": "SFTP support requires 'paramiko'. Please ensure it is installed in requirements.txt."}

        is_valid, err = validate_host(host)
        if not is_valid:
            return {"success": False, "message": err}

        test_ssh = None
        try:
            port_num = int(port)
            test_ssh = paramiko.SSHClient()
            test_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            test_ssh.connect(
                host.strip(),
                port=port_num,
                username=username.strip() if username else "",
                password=password if password else "",
                timeout=8,
                look_for_keys=False,
                allow_agent=False
            )
            sftp_chan = test_ssh.open_sftp()
            sftp_chan.close()
            test_ssh.close()
            return {
                "success": True,
                "message": f"SFTP connection test succeeded! SSH host reachable at {host}:{port_num} with valid credentials.",
                "protocol": "sftp"
            }
        except paramiko.AuthenticationException:
            return {"success": False, "message": "SSH host reachable, but authentication failed (Invalid SFTP username/password)."}
        except ConnectionRefusedError:
            return {"success": False, "message": f"SSH connection refused at {host}:{port}. Is SSH running?"}
        except Exception as e:
            return {"success": False, "message": f"SFTP connection test failed: {str(e)}"}
        finally:
            if test_ssh:
                try:
                    test_ssh.close()
                except Exception:
                    pass

    def is_alive(self):
        if not self.ssh or not self.sftp or not self.connected:
            return False
        try:
            transport = self.ssh.get_transport()
            if transport and transport.is_active():
                return True
            self.connected = False
            return False
        except Exception:
            self.connected = False
            return False

    def get_current_directory(self):
        return self.current_dir or "/"

    def list_files(self):
        if not self.connected or not self.sftp:
            return {"success": False, "message": "SFTP server is not connected.", "files": []}

        try:
            items = []
            dir_attrs = self.sftp.listdir_attr(self.current_dir)
            for attr in dir_attrs:
                name = attr.filename
                if name in [".", ".."]:
                    continue
                is_dir = stat.S_ISDIR(attr.st_mode) if attr.st_mode is not None else False
                size = attr.st_size if attr.st_size is not None and not is_dir else 0
                mod_time = ""
                if attr.st_mtime:
                    try:
                        mod_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(attr.st_mtime))
                    except Exception:
                        mod_time = ""

                items.append({
                    "name": name,
                    "type": "directory" if is_dir else "file",
                    "size": size,
                    "modified": mod_time
                })

            items.sort(key=lambda x: (0 if x["type"] == "directory" else 1, x["name"].lower()))
            self.last_activity = time.time()
            return {"success": True, "current_directory": self.current_dir, "files": items}

        except IOError as e:
            return {"success": False, "message": f"SFTP directory read error: {str(e)}", "files": []}
        except Exception as e:
            return {"success": False, "message": f"Failed to list SFTP directory: {str(e)}", "files": []}

    def change_directory(self, target_folder):
        if not self.connected or not self.sftp:
            return {"success": False, "message": "SFTP server is not connected."}
        clean_folder = sanitize_filename(target_folder)
        if not clean_folder:
            return {"success": False, "message": "Invalid directory name specified."}

        target_path = posixpath.join(self.current_dir, clean_folder)
        try:
            self.sftp.chdir(target_path)
            self.current_dir = self.sftp.normalize(".")
            self.last_activity = time.time()
            return {"success": True, "message": f"Navigated into '{clean_folder}'.", "current_directory": self.current_dir}
        except IOError as e:
            return {"success": False, "message": f"Cannot enter directory '{clean_folder}': {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"SFTP navigation error: {str(e)}"}

    def change_to_parent(self):
        if not self.connected or not self.sftp:
            return {"success": False, "message": "SFTP server is not connected."}

        # Calculate parent path safely
        parent_path = posixpath.dirname(self.current_dir.rstrip("/")) or "/"
        try:
            self.sftp.chdir(parent_path)
            self.current_dir = self.sftp.normalize(".")
            self.last_activity = time.time()
            return {"success": True, "message": "Navigated to parent directory.", "current_directory": self.current_dir}
        except Exception as e:
            return {"success": False, "message": f"Error navigating up: {str(e)}"}

    def create_directory(self, folder_name):
        if not self.connected or not self.sftp:
            return {"success": False, "message": "SFTP server is not connected."}
        clean_name = sanitize_filename(folder_name)
        if not clean_name:
            return {"success": False, "message": "Invalid folder name specified."}

        target_path = posixpath.join(self.current_dir, clean_name)
        try:
            self.sftp.mkdir(target_path)
            self.last_activity = time.time()
            return {"success": True, "message": f"Directory '{clean_name}' created successfully via SFTP."}
        except IOError as e:
            return {"success": False, "message": f"SFTP mkdir failed (Folder exists or permission denied): {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Error creating folder '{clean_name}': {str(e)}"}

    def rename_item(self, old_name, new_name):
        if not self.connected or not self.sftp:
            return {"success": False, "message": "SFTP server is not connected."}
        clean_old = sanitize_filename(old_name)
        clean_new = sanitize_filename(new_name)
        if not clean_old or not clean_new:
            return {"success": False, "message": "Invalid filename specified for rename."}

        src_path = posixpath.join(self.current_dir, clean_old)
        dest_path = posixpath.join(self.current_dir, clean_new)

        try:
            self.sftp.rename(src_path, dest_path)
            self.last_activity = time.time()
            return {"success": True, "message": f"Successfully renamed '{clean_old}' to '{clean_new}' via SFTP."}
        except IOError as e:
            return {"success": False, "message": f"SFTP rename failed: {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Error renaming item: {str(e)}"}

    def upload_file(self, filename, file_stream):
        if not self.connected or not self.sftp:
            return {"success": False, "message": "SFTP server is not connected."}
        clean_name = sanitize_filename(filename)
        if not clean_name:
            return {"success": False, "message": "Invalid filename for upload."}

        dest_path = posixpath.join(self.current_dir, clean_name)
        try:
            file_stream.seek(0)
            self.sftp.putfo(file_stream, dest_path)
            self.last_activity = time.time()
            return {"success": True, "message": f"Successfully uploaded '{clean_name}' via SFTP."}
        except IOError as e:
            return {"success": False, "message": f"SFTP upload permission denied: {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"SFTP upload failed: {str(e)}"}

    def download_to_tempfile(self, filename):
        if not self.connected or not self.sftp:
            return {"success": False, "message": "SFTP server is not connected.", "temp_path": None}
        clean_name = sanitize_filename(filename)
        if not clean_name:
            return {"success": False, "message": "Invalid filename for download.", "temp_path": None}

        src_path = posixpath.join(self.current_dir, clean_name)
        temp_file = None
        try:
            temp_file = tempfile.NamedTemporaryFile(delete=False, prefix="nettransfer_dl_")
            temp_path = temp_file.name

            self.sftp.getfo(src_path, temp_file)
            temp_file.flush()
            temp_file.close()

            self.last_activity = time.time()
            return {"success": True, "message": f"Successfully retrieved '{clean_name}' via SFTP.", "temp_path": temp_path, "clean_filename": clean_name}
        except IOError as e:
            if temp_file and os.path.exists(temp_file.name):
                try:
                    os.remove(temp_file.name)
                except Exception:
                    pass
            return {"success": False, "message": f"SFTP download error (File not found or permission denied): {str(e)}", "temp_path": None}
        except Exception as e:
            if temp_file and os.path.exists(temp_file.name):
                try:
                    os.remove(temp_file.name)
                except Exception:
                    pass
            return {"success": False, "message": f"SFTP download failed: {str(e)}", "temp_path": None}

    def delete_item(self, item_name, is_dir=False):
        if not self.connected or not self.sftp:
            return {"success": False, "message": "SFTP server is not connected."}
        clean_name = sanitize_filename(item_name)
        if not clean_name:
            return {"success": False, "message": "Invalid name specified for deletion."}

        target_path = posixpath.join(self.current_dir, clean_name)
        try:
            if is_dir:
                self.sftp.rmdir(target_path)
                msg = f"Directory '{clean_name}' removed successfully via SFTP."
            else:
                self.sftp.remove(target_path)
                msg = f"File '{clean_name}' deleted successfully via SFTP."
            self.last_activity = time.time()
            return {"success": True, "message": msg}
        except IOError as e:
            return {"success": False, "message": f"SFTP delete error (Directory not empty or permission denied): {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Failed to delete '{clean_name}': {str(e)}"}

    def disconnect(self):
        if self.sftp:
            try:
                self.sftp.close()
            except Exception:
                pass
            self.sftp = None
        if self.ssh:
            try:
                self.ssh.close()
            except Exception:
                pass
            self.ssh = None
        self.connected = False
        self.host = None
        self.username = None
        self.current_dir = "/"
        return {"success": True, "message": "Disconnected from SFTP server."}


def create_client_instance(protocol="ftp"):
    """Factory creating appropriate client instance based on protocol."""
    proto = (protocol or "ftp").lower().strip()
    if proto == "ftps":
        return FTPSClient()
    elif proto == "sftp":
        return SFTPClient()
    return FTPClient()


# ==============================================================================
# 4. SESSION MANAGER
# ==============================================================================
class SessionManager:
    """
    Safely maintains isolated transfer clients per user session.
    Automatically purges inactive sessions after 15 minutes.
    """

    def __init__(self):
        self._sessions = {}

    def get_client(self, session_id, protocol=None):
        self.cleanup_stale_sessions()
        current_client = self._sessions.get(session_id)

        # If protocol changed or client not created yet, instantiate new client
        if current_client is None:
            self._sessions[session_id] = create_client_instance(protocol)
        elif protocol and current_client.protocol != protocol.lower().strip():
            try:
                current_client.disconnect()
            except Exception:
                pass
            self._sessions[session_id] = create_client_instance(protocol)

        return self._sessions[session_id]

    def remove_session(self, session_id):
        if session_id in self._sessions:
            try:
                self._sessions[session_id].disconnect()
            except Exception:
                pass
            del self._sessions[session_id]

    def cleanup_stale_sessions(self):
        now = time.time()
        stale_ids = []
        for sid, client in self._sessions.items():
            if now - client.last_activity > SESSION_IDLE_TIMEOUT_SECONDS:
                stale_ids.append(sid)
        for sid in stale_ids:
            try:
                self._sessions[sid].disconnect()
            except Exception:
                pass
            del self._sessions[sid]


# Global session manager instance
session_manager = SessionManager()
