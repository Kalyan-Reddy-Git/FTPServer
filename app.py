"""
app.py
Flask web server for NetTransfer – FTP File Transfer System
Course: Computer Networks and Ethical Hacking
Project: Implementation of Application Layer Protocols (FTP RFC 959)

SECURITY PRACTICES:
- Application secrets configured via environment variables with fallback
- Debug mode disabled by default unless explicitly enabled via FLASK_DEBUG
- Passwords are never logged, exposed in responses, or stored on disk
- Filename sanitization to prevent directory traversal attacks
- Temporary download files are safely cleaned up after transmission
- Connection state isolated per user session; proxy abuse prevented
"""

import os
import uuid
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    send_file,
    after_this_request
)
from werkzeug.utils import secure_filename
from ftp_service import session_manager, sanitize_filename

app = Flask(__name__)

# Use environment variable for session secret, falling back to secure random bytes
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Restrict maximum upload payload to 50 MB
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024


def get_current_session_client():
    """
    Retrieves or initializes the isolated FTPClient instance for the current session.
    Prevents open proxy vulnerabilities by binding clients to unique session tokens.
    """
    if 'user_session_id' not in session:
        session['user_session_id'] = str(uuid.uuid4())
    return session_manager.get_client(session['user_session_id'])


@app.route('/')
def index():
    """Renders the main single-page user interface."""
    return render_template('index.html')


@app.route('/api/connect', methods=['POST'])
def api_connect():
    """
    Endpoint: Connect to FTP Server
    Accepts: JSON { host, port, username, password }
    Establishes an Application Layer control connection using RFC 959 USER/PASS.
    NOTE: The password is used in-memory for authentication and NEVER returned in the response.
    """
    data = request.get_json() or {}
    host = str(data.get('host', '')).strip()
    port = data.get('port', 21)
    username = str(data.get('username', 'anonymous')).strip()
    password = str(data.get('password', ''))

    if not host:
        return jsonify({
            'success': False,
            'message': 'Server IP address or hostname is required.'
        }), 400

    client = get_current_session_client()
    result = client.connect(host=host, port=port, username=username, password=password)

    if result.get('success'):
        session['connected_host'] = client.host
        session['connected_port'] = client.port
        session['connected_user'] = client.username
        return jsonify({
            'success': True,
            'message': result.get('message'),
            'host': client.host,
            'port': client.port,
            'username': client.username,
            'current_directory': result.get('current_directory', '/')
        })
    else:
        return jsonify({
            'success': False,
            'message': result.get('message')
        }), 400


@app.route('/api/disconnect', methods=['POST'])
def api_disconnect():
    """
    Endpoint: Disconnect from FTP Server
    Terminates the control connection via the QUIT command and clears session state.
    """
    client = get_current_session_client()
    result = client.disconnect()

    session.pop('connected_host', None)
    session.pop('connected_port', None)
    session.pop('connected_user', None)

    return jsonify(result)


@app.route('/api/status', methods=['GET'])
def api_status():
    """
    Endpoint: Query Connection Status
    Returns the real-time operational state of the FTP connection.
    """
    client = get_current_session_client()
    is_connected = client.connected and client.is_alive()

    if not is_connected:
        client.connected = False
        return jsonify({'connected': False})

    return jsonify({
        'connected': True,
        'host': client.host,
        'port': client.port,
        'username': client.username,
        'current_directory': client.get_current_directory()
    })


@app.route('/api/files', methods=['GET'])
def api_files():
    """
    Endpoint: List Remote Files
    Queries the remote FTP server and returns real directory contents.
    Enforces server-side permissions and handles errors gracefully.
    """
    client = get_current_session_client()
    if not client.connected or not client.is_alive():
        return jsonify({'success': False, 'message': 'No active FTP connection. Please connect first.'}), 400

    result = client.list_files()
    if result.get('success'):
        return jsonify(result)
    else:
        return jsonify(result), 500


@app.route('/api/cwd', methods=['POST'])
def api_cwd():
    """
    Endpoint: Navigate Remote Directories
    Accepts: JSON { path: string, action: 'into' | 'parent' }
    Sends CWD or CDUP command to the FTP server. Validates directory names against path traversal.
    """
    client = get_current_session_client()
    if not client.connected or not client.is_alive():
        return jsonify({'success': False, 'message': 'No active FTP connection. Please connect first.'}), 400

    data = request.get_json() or {}
    action = data.get('action', 'into')

    if action == 'parent':
        result = client.change_to_parent()
    else:
        target_path = data.get('path', '')
        result = client.change_directory(target_path)

    if result.get('success'):
        # Return updated file list along with directory change response
        list_res = client.list_files()
        return jsonify({
            'success': True,
            'message': result.get('message'),
            'current_directory': client.get_current_directory(),
            'files': list_res.get('files', [])
        })
    else:
        return jsonify(result), 400


@app.route('/api/upload', methods=['POST'])
def api_upload():
    """
    Endpoint: Upload File to FTP Server
    Accepts: Multipart/form-data with 'file' field.
    Validates file presence, filename sanitization, and streams data using the STOR command.
    """
    client = get_current_session_client()
    if not client.connected or not client.is_alive():
        return jsonify({'success': False, 'message': 'No active FTP connection. Please connect first.'}), 400

    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part found in upload request.'}), 400

    uploaded_file = request.files['file']
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({'success': False, 'message': 'No file was selected for upload.'}), 400

    # Sanitize filename and prevent path traversal
    safe_name = sanitize_filename(uploaded_file.filename)
    if not safe_name:
        return jsonify({'success': False, 'message': 'Invalid filename supplied for upload.'}), 400

    result = client.upload_file(safe_name, uploaded_file.stream)
    if result.get('success'):
        return jsonify(result)
    else:
        return jsonify(result), 400


@app.route('/api/download', methods=['GET'])
def api_download():
    """
    Endpoint: Download File from FTP Server
    Query parameter: ?filename=<name>
    Retrieves the file via RETR into a temporary file, streams it to the user as an attachment,
    and safely unlinks the temporary file after transmission.
    """
    client = get_current_session_client()
    if not client.connected or not client.is_alive():
        return jsonify({'success': False, 'message': 'No active FTP connection. Please connect first.'}), 400

    raw_filename = request.args.get('filename', '')
    clean_filename = sanitize_filename(raw_filename)
    if not clean_filename:
        return jsonify({'success': False, 'message': 'Invalid filename specified for download.'}), 400

    result = client.download_to_tempfile(clean_filename)

    if not result.get('success') or not result.get('temp_path'):
        return jsonify({
            'success': False,
            'message': result.get('message', 'Failed to retrieve file from FTP server.')
        }), 400

    temp_path = result['temp_path']

    # Register an after-request hook to safely clean up the temporary file
    @after_this_request
    def remove_temp_file(response):
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
        return response

    return send_file(
        temp_path,
        as_attachment=True,
        download_name=clean_filename,
        mimetype='application/octet-stream'
    )


@app.route('/api/delete', methods=['POST'])
def api_delete():
    """
    Endpoint: Delete File or Directory
    Accepts: JSON { name: string, type: 'file' | 'directory' }
    Sends DELE (for files) or RMD (for directories) to the remote server.
    """
    client = get_current_session_client()
    if not client.connected or not client.is_alive():
        return jsonify({'success': False, 'message': 'No active FTP connection. Please connect first.'}), 400

    data = request.get_json() or {}
    item_name = data.get('name', '')
    item_type = data.get('type', 'file')

    clean_name = sanitize_filename(item_name)
    if not clean_name:
        return jsonify({'success': False, 'message': 'Invalid item name for deletion.'}), 400

    result = client.delete_item(clean_name, is_dir=(item_type == 'directory'))
    if result.get('success'):
        return jsonify(result)
    else:
        return jsonify(result), 400


if __name__ == '__main__':
    # Determine debug mode from environment (defaults to False for production safety)
    is_debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1')

    print("==================================================================")
    print("  NetTransfer – FTP File Transfer System (Flask Backend)")
    print("  Course Project: Implementation of Application Layer Protocols")
    print(f"  Debug Mode : {is_debug}")
    print("  Access Web Interface at: http://127.0.0.1:5000")
    print("==================================================================")

    app.run(host='127.0.0.1', port=5000, debug=is_debug)
