"""
ftp_service.py
Core FTP client implementation using Python's standard `ftplib`.
Course: Computer Networks and Ethical Hacking
Project: NetTransfer - Implementation of Application Layer Protocols (FTP RFC 959)

SECURITY FEATURES:
- In-memory session isolation (no persistent credential storage)
- Passwords are never logged, printed, or exposed in output
- Strict path sanitization preventing path traversal
- Passive mode (PASV) data connections
- Safe temporary file streaming for downloads
"""

import os
import re
import time
import socket
import tempfile
from ftplib import FTP, error_perm, error_temp, error_proto, error_reply

# Maximum idle timeout for an inactive FTP session (15 minutes)
SESSION_IDLE_TIMEOUT_SECONDS = 900

def sanitize_filename(filename):
    """
    Sanitizes filename and prevents directory traversal attacks.
    Ensures filename is strictly a single filename with no path separators.
    """
    if not filename:
        return ""
    # Strip any directory path components (both UNIX / and Windows \)
    clean_name = os.path.basename(filename.replace("\\", "/"))
    # Remove null bytes and control characters
    clean_name = re.sub(r"[\x00-\x1f\x7f]", "", clean_name)
    # Disallow relative navigation names
    if clean_name in [".", ".."]:
        return ""
    return clean_name


class FTPClient:
    """Encapsulates ftplib.FTP operations for a single client session."""

    def __init__(self):
        self.ftp = None
        self.host = None
        self.port = 21
        self.username = None
        self.connected = False
        self.last_activity = time.time()

    def connect(self, host, port=21, username="anonymous", password=""):
        """
        Establishes an Application Layer control connection and authenticates
        using RFC 959 USER and PASS commands.
        Credentials are used strictly in-memory and never logged or persisted.
        """
        self.disconnect()  # Clean up any existing connection

        self.host = host.strip()
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
            
            # Step 1: Open TCP Control Connection (typically Port 21)
            welcome_msg = self.ftp.connect(self.host, self.port, timeout=10)

            # Step 2: Authenticate (USER and PASS commands)
            # Passwords are NOT saved to self attributes or printed anywhere
            login_msg = self.ftp.login(self.username, auth_password)

            # Step 3: Enable Passive Mode (PASV) for data connections
            self.ftp.set_pasv(True)
            self.connected = True
            self.last_activity = time.time()

            current_dir = self.get_current_directory()
            return {
                "success": True,
                "message": f"Connected to {self.host}:{self.port} as '{self.username}'.",
                "welcome": welcome_msg,
                "current_directory": current_dir
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
                "message": f"Connection timed out while reaching {self.host}:{self.port}. Verify server IP and network firewall settings."
            }
        except socket.gaierror:
            self.connected = False
            return {
                "success": False,
                "message": f"Could not resolve hostname '{self.host}'. Check the server domain or IP address."
            }
        except error_perm as e:
            self.connected = False
            err_text = str(e)
            if "530" in err_text:
                return {
                    "success": False,
                    "message": "Authentication failed (530 Login incorrect). Please check your username and password."
                }
            return {
                "success": False,
                "message": f"FTP Permission Error: {err_text}"
            }
        except Exception as e:
            self.connected = False
            return {
                "success": False,
                "message": f"Connection error: {str(e)}"
            }

    def is_alive(self):
        """Verifies if the control connection is still responsive."""
        if not self.ftp or not self.connected:
            return False
        try:
            self.ftp.voidcmd("NOOP")
            return True
        except Exception:
            self.connected = False
            return False

    def get_current_directory(self):
        """Returns the current remote working directory (PWD command)."""
        if not self.connected or not self.ftp:
            return "/"
        try:
            return self.ftp.pwd()
        except Exception:
            return "/"

    def list_files(self):
        """
        Lists real files and directories in current working directory.
        Uses modern MLSD command (RFC 3659) with fallback to standard LIST (RFC 959).
        """
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected.", "files": []}

        try:
            current_dir = self.get_current_directory()
            items = []
            supports_mlsd = True

            # Primary Method: RFC 3659 MLSD (Standard machine-readable listing)
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

            # Fallback Method: RFC 959 LIST command
            if not supports_mlsd:
                items = self._fallback_list()

            # Sort: Directories first, then alphabetically
            items.sort(key=lambda x: (0 if x["type"] == "directory" else 1, x["name"].lower()))
            self.last_activity = time.time()

            return {
                "success": True,
                "current_directory": current_dir,
                "files": items
            }

        except error_perm as e:
            return {"success": False, "message": f"Permission denied while reading directory: {str(e)}", "files": []}
        except Exception as e:
            return {"success": False, "message": f"Failed to list directory contents: {str(e)}", "files": []}

    def _fallback_list(self):
        """Parses standard UNIX or DOS directory listings returned by LIST."""
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

            # Standard UNIX format: drwxr-xr-x 2 owner group 4096 Oct 10 12:00 filename
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
            elif len(line_clean.split()) >= 4 and ("<DIR>" in line_clean or ":" in line_clean):
                # DOS format: 10-10-26 09:15PM <DIR> foldername
                dos_parts = line_clean.split(maxsplit=3)
                if len(dos_parts) == 4:
                    is_dir = "<DIR>" in dos_parts[2]
                    try:
                        size = 0 if is_dir else int(dos_parts[2].replace(",", ""))
                    except ValueError:
                        size = 0
                    name = dos_parts[3].strip()
                    if name not in [".", ".."]:
                        items.append({
                            "name": name,
                            "type": "directory" if is_dir else "file",
                            "size": size,
                            "modified": f"{dos_parts[0]} {dos_parts[1]}"
                        })
            else:
                name = line_clean
                if name and name not in [".", ".."]:
                    items.append({
                        "name": name,
                        "type": "file",
                        "size": 0,
                        "modified": ""
                    })
        return items

    def change_directory(self, target_folder):
        """
        Changes remote working directory (CWD command).
        Validates target folder name to prevent arbitrary traversal.
        """
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected."}

        clean_folder = sanitize_filename(target_folder)
        if not clean_folder:
            return {"success": False, "message": "Invalid directory name specified."}

        try:
            res = self.ftp.cwd(clean_folder)
            self.last_activity = time.time()
            return {
                "success": True,
                "message": f"Directory changed to '{clean_folder}'.",
                "current_directory": self.get_current_directory()
            }
        except error_perm as e:
            return {"success": False, "message": f"Cannot access directory '{clean_folder}': {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Directory navigation error: {str(e)}"}

    def change_to_parent(self):
        """
        Changes remote working directory to parent directory (CDUP / CWD ..).
        """
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected."}

        try:
            try:
                self.ftp.cwd("..")
            except Exception:
                self.ftp.voidcmd("CDUP")

            self.last_activity = time.time()
            return {
                "success": True,
                "message": "Navigated to parent directory.",
                "current_directory": self.get_current_directory()
            }
        except error_perm as e:
            return {"success": False, "message": f"Already at root directory or permission denied: {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Error navigating up: {str(e)}"}

    def upload_file(self, filename, file_stream):
        """
        Uploads a file to the current working directory on the FTP server (STOR command).
        Validates the filename to prevent path traversal.
        """
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected."}

        clean_name = sanitize_filename(filename)
        if not clean_name:
            return {"success": False, "message": "Invalid filename for upload."}

        try:
            file_stream.seek(0)
            command = f"STOR {clean_name}"
            self.ftp.storbinary(command, file_stream)
            self.last_activity = time.time()
            return {
                "success": True,
                "message": f"Successfully uploaded '{clean_name}' to FTP server."
            }
        except error_perm as e:
            return {"success": False, "message": f"Upload permission denied by FTP server (550): {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Failed to upload '{clean_name}': {str(e)}"}

    def download_to_tempfile(self, filename):
        """
        Downloads a remote file from the current working directory via RETR command
        into a secure temporary file on disk.
        Returns the path to the temporary file so it can be streamed to the client
        and safely unlinked afterwards.
        """
        if not self.connected or not self.ftp:
            return {"success": False, "message": "FTP server is not connected.", "temp_path": None}

        clean_name = sanitize_filename(filename)
        if not clean_name:
            return {"success": False, "message": "Invalid filename for download.", "temp_path": None}

        temp_file = None
        try:
            # Create a secure temporary file on the local filesystem
            temp_file = tempfile.NamedTemporaryFile(delete=False, prefix="nettransfer_dl_")
            temp_path = temp_file.name

            # Stream remote file binary chunks directly into temporary file
            command = f"RETR {clean_name}"
            self.ftp.retrbinary(command, temp_file.write)
            temp_file.flush()
            temp_file.close()

            self.last_activity = time.time()
            return {
                "success": True,
                "message": f"Successfully retrieved '{clean_name}'.",
                "temp_path": temp_path,
                "clean_filename": clean_name
            }

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
        """
        Deletes a file (DELE) or directory (RMD) from the remote FTP server.
        """
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
        """Sends RFC 959 QUIT command and safely terminates the socket connection."""
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


class SessionManager:
    """
    Safely maintains isolated, in-memory FTPClient instances per user session.
    Automatically purges inactive sessions after the timeout duration.
    """

    def __init__(self):
        self._sessions = {}

    def get_client(self, session_id):
        self.cleanup_stale_sessions()
        if session_id not in self._sessions:
            self._sessions[session_id] = FTPClient()
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
