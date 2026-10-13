"""
app.py
Flask web server for NetTransfer – FTP, FTPS, and SFTP File Transfer System
Course: Computer Networks and Ethical Hacking
Project: Implementation of Application Layer Protocols

SECURITY PRACTICES:
- Multi-protocol dispatch (FTP, FTPS, SFTP) with session isolation
- Strict path sanitization preventing directory traversal
- SSRF filtering on remote hosts
- Passwords are never logged, exposed in responses, or stored on disk
- Safe temporary download streaming with immediate cleanup
- Production debug disabled unless explicit FLASK_DEBUG is provided
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
from ftp_service import (
    session_manager,
    sanitize_filename,
    validate_host,
    create_client_instance
)

app = Flask(__name__)

# Use environment variable for session secret, falling back to secure random bytes
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Restrict maximum upload payload to 50 MB
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024


def get_current_session_client(protocol=None):
    """
    Retrieves or initializes the isolated client instance for the current session.
    Binds clients to unique session tokens to prevent open proxy vulnerabilities.
    """
    if 'user_session_id' not in session:
        session['user_session_id'] = str(uuid.uuid4())
    return session_manager.get_client(session['user_session_id'], protocol=protocol)


@app.route('/')
def index():
    """Renders the main single-page user interface."""
    return render_template('index.html')


@app.route('/api/connect', methods=['POST'])
def api_connect():
    """
    Endpoint: Connect to Server
    Accepts: JSON { host, port, username, password, protocol: 'ftp' | 'ftps' | 'sftp' }
    Establishes connection using specified Application Layer protocol.
    NOTE: The password is used in-memory for authentication and NEVER returned in the response.
    """
    data = request.get_json() or {}
    host = str(data.get('host', '')).strip()
    protocol = str(data.get('protocol', 'ftp')).lower().strip()
    port = data.get('port')
    username = str(data.get('username', 'anonymous')).strip()
    password = str(data.get('password', ''))

    if protocol not in ['ftp', 'ftps', 'sftp']:
        protocol = 'ftp'

    # Assign default port if unspecified or invalid
    try:
        port = int(port)
    except (ValueError, TypeError):
        port = 22 if protocol == 'sftp' else 21

    is_valid, err_msg = validate_host(host)
    if not is_valid:
        return jsonify({'success': False, 'message': err_msg}), 400

    client = get_current_session_client(protocol=protocol)
    result = client.connect(host=host, port=port, username=username, password=password)

    if result.get('success'):
        session['connected_host'] = client.host
        session['connected_port'] = client.port
        session['connected_user'] = client.username
        session['connected_protocol'] = protocol
        return jsonify({
            'success': True,
            'message': result.get('message'),
            'host': client.host,
            'port': client.port,
            'username': client.username,
            'protocol': protocol,
            'current_directory': result.get('current_directory', '/')
        })
    else:
        return jsonify({
            'success': False,
            'message': result.get('message')
        }), 400


@app.route('/api/test-connect', methods=['POST'])
def api_test_connect():
    """
    Endpoint: Test Connection
    Accepts: JSON { host, port, username, password, protocol }
    Runs a test handshake and terminates immediately without altering the active session.
    """
    data = request.get_json() or {}
    host = str(data.get('host', '')).strip()
    protocol = str(data.get('protocol', 'ftp')).lower().strip()
    port = data.get('port')
    username = str(data.get('username', 'anonymous')).strip()
    password = str(data.get('password', ''))

    if protocol not in ['ftp', 'ftps', 'sftp']:
        protocol = 'ftp'

    try:
        port = int(port)
    except (ValueError, TypeError):
        port = 22 if protocol == 'sftp' else 21

    is_valid, err_msg = validate_host(host)
    if not is_valid:
        return jsonify({'success': False, 'message': err_msg}), 400

    # Instantiate a temporary client strictly for testing
    test_client = create_client_instance(protocol=protocol)
    result = test_client.test_connection(host=host, port=port, username=username, password=password)

    status_code = 200 if result.get('success') else 400
    return jsonify(result), status_code


@app.route('/api/disconnect', methods=['POST'])
def api_disconnect():
    """
    Endpoint: Disconnect from Server
    Terminates active session cleanly and clears session credentials.
    """
    client = get_current_session_client()
    result = client.disconnect()

    session.pop('connected_host', None)
    session.pop('connected_port', None)
    session.pop('connected_user', None)
    session.pop('connected_protocol', None)

    return jsonify(result)


@app.route('/api/status', methods=['GET'])
def api_status():
    """
    Endpoint: Query Connection Status
    Returns the real-time operational state of the connection.
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
        'protocol': getattr(client, 'protocol', 'ftp'),
        'current_directory': client.get_current_directory()
    })


@app.route('/api/files', methods=['GET'])
def api_files():
    """
    Endpoint: List Remote Files
    Queries the remote server and returns real directory contents.
    """
    client = get_current_session_client()
    if not client.connected or not client.is_alive():
        return jsonify({'success': False, 'message': 'No active connection. Please connect first.'}), 400

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
    """
    client = get_current_session_client()
    if not client.connected or not client.is_alive():
        return jsonify({'success': False, 'message': 'No active connection. Please connect first.'}), 400

    data = request.get_json() or {}
    action = data.get('action', 'into')

    if action == 'parent':
        result = client.change_to_parent()
    else:
        target_path = data.get('path', '')
        result = client.change_directory(target_path)

    if result.get('success'):
        list_res = client.list_files()
        return jsonify({
            'success': True,
            'message': result.get('message'),
            'current_directory': client.get_current_directory(),
            'files': list_res.get('files', [])
        })
    else:
        return jsonify(result), 400


@app.route('/api/mkdir', methods=['POST'])
def api_mkdir():
    """
    Endpoint: Create Remote Directory
    Accepts: JSON { folder_name: string }
    Creates a new folder in the current working directory.
    """
    client = get_current_session_client()
    if not client.connected or not client.is_alive():
        return jsonify({'success': False, 'message': 'No active connection. Please connect first.'}), 400

    data = request.get_json() or {}
    folder_name = data.get('folder_name', '')
    clean_folder = sanitize_filename(folder_name)

    if not clean_folder:
        return jsonify({'success': False, 'message': 'Please provide a valid folder name.'}), 400

    result = client.create_directory(clean_folder)
    if result.get('success'):
        list_res = client.list_files()
        return jsonify({
            'success': True,
            'message': result.get('message'),
            'current_directory': client.get_current_directory(),
            'files': list_res.get('files', [])
        })
    else:
        return jsonify(result), 400


@app.route('/api/rename', methods=['POST'])
def api_rename():
    """
    Endpoint: Rename File or Directory
    Accepts: JSON { old_name: string, new_name: string, type: 'file' | 'directory' }
    """
    client = get_current_session_client()
    if not client.connected or not client.is_alive():
        return jsonify({'success': False, 'message': 'No active connection. Please connect first.'}), 400

    data = request.get_json() or {}
    old_name = data.get('old_name', '')
    new_name = data.get('new_name', '')

    clean_old = sanitize_filename(old_name)
    clean_new = sanitize_filename(new_name)

    if not clean_old or not clean_new:
        return jsonify({'success': False, 'message': 'Invalid file or directory names provided.'}), 400

    if clean_old == clean_new:
        return jsonify({'success': False, 'message': 'New name must be different from current name.'}), 400

    result = client.rename_item(clean_old, clean_new)
    if result.get('success'):
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
    Endpoint: Upload File
    Accepts: Multipart/form-data with 'file' field.
    """
    client = get_current_session_client()
    if not client.connected or not client.is_alive():
        return jsonify({'success': False, 'message': 'No active connection. Please connect first.'}), 400

    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part found in upload request.'}), 400

    uploaded_file = request.files['file']
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({'success': False, 'message': 'No file was selected for upload.'}), 400

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
    Endpoint: Download File
    Query parameter: ?filename=<name>
    Streams file via temporary file and immediately unlinks it after transfer.
    """
    client = get_current_session_client()
    if not client.connected or not client.is_alive():
        return jsonify({'success': False, 'message': 'No active connection. Please connect first.'}), 400

    raw_filename = request.args.get('filename', '')
    clean_filename = sanitize_filename(raw_filename)
    if not clean_filename:
        return jsonify({'success': False, 'message': 'Invalid filename specified for download.'}), 400

    result = client.download_to_tempfile(clean_filename)
    if not result.get('success') or not result.get('temp_path'):
        return jsonify({
            'success': False,
            'message': result.get('message', 'Failed to retrieve file from remote server.')
        }), 400

    temp_path = result['temp_path']

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
    """
    client = get_current_session_client()
    if not client.connected or not client.is_alive():
        return jsonify({'success': False, 'message': 'No active connection. Please connect first.'}), 400

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
    is_debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1')
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))

    print("==================================================================")
    print("  NetTransfer – Multi-Protocol File Transfer System (FTP/FTPS/SFTP)")
    print("  Course Project: Implementation of Application Layer Protocols")
    print(f"  Debug Mode : {is_debug}")
    print(f"  Listening on: http://{host}:{port}")
    print("==================================================================")

    app.run(host=host, port=port, debug=is_debug)
