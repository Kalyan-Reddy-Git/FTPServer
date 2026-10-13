/**
 * app.js
 * Frontend controller for NetTransfer – Multi-Protocol File Transfer System (FTP, FTPS, SFTP)
 * Course: Computer Networks and Ethical Hacking
 * Project: Implementation of Application Layer Protocols
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements - Connection
    const ftpConnectForm = document.getElementById('ftpConnectForm');
    const serverProtocolSelect = document.getElementById('serverProtocol');
    const serverHostInput = document.getElementById('serverHost');
    const serverPortInput = document.getElementById('serverPort');
    const portHint = document.getElementById('portHint');
    const serverUserInput = document.getElementById('serverUser');
    const serverPassInput = document.getElementById('serverPass');
    const btnConnect = document.getElementById('btnConnect');
    const btnTestConnect = document.getElementById('btnTestConnect');
    const btnDisconnect = document.getElementById('btnDisconnect');
    const connectSpinner = document.getElementById('connectSpinner');
    const testSpinner = document.getElementById('testSpinner');
    const connectionBadge = document.getElementById('connectionBadge');
    const badgeStatusText = document.getElementById('badgeStatusText');
    const navStatusChip = document.getElementById('navStatusChip');
    const navStatusText = document.getElementById('navStatusText');
    const connectionAlert = document.getElementById('connectionAlert');
    const alertMessage = document.getElementById('alertMessage');
    const protocolSecurityNotice = document.getElementById('protocolSecurityNotice');

    // DOM Elements - Hero & Quick Fill
    const btnScrollConnect = document.getElementById('btnScrollConnect');
    const btnFillDemo = document.getElementById('btnFillDemo');

    // DOM Elements - File Manager
    const currentDirectoryPath = document.getElementById('currentDirectoryPath');
    const btnParentDir = document.getElementById('btnParentDir');
    const btnRefreshFiles = document.getElementById('btnRefreshFiles');
    const btnNewFolder = document.getElementById('btnNewFolder');
    const fileUploadInput = document.getElementById('fileUploadInput');
    const btnUploadLabel = document.getElementById('btnUploadLabel');
    const uploadProgressBox = document.getElementById('uploadProgressBox');
    const uploadFileName = document.getElementById('uploadFileName');
    const uploadPercent = document.getElementById('uploadPercent');
    const uploadProgressBarFill = document.getElementById('uploadProgressBarFill');
    const fileTableBody = document.getElementById('fileTableBody');

    // DOM Elements - Modals
    const mkdirModal = document.getElementById('mkdirModal');
    const newFolderNameInput = document.getElementById('newFolderName');
    const btnCloseMkdirModal = document.getElementById('btnCloseMkdirModal');
    const btnCancelMkdir = document.getElementById('btnCancelMkdir');
    const btnSubmitMkdir = document.getElementById('btnSubmitMkdir');

    const renameModal = document.getElementById('renameModal');
    const renameOldNameInput = document.getElementById('renameOldName');
    const renameItemTypeInput = document.getElementById('renameItemType');
    const renameNewNameInput = document.getElementById('renameNewName');
    const btnCloseRenameModal = document.getElementById('btnCloseRenameModal');
    const btnCancelRename = document.getElementById('btnCancelRename');
    const btnSubmitRename = document.getElementById('btnSubmitRename');

    // DOM Elements - Activity Log
    const logContainer = document.getElementById('logContainer');
    const btnClearLogs = document.getElementById('btnClearLogs');

    // State Variables
    let isConnected = false;
    let currentDir = '/';
    let currentProtocol = 'ftp';

    // =========================================================================
    // UTILITY FUNCTIONS
    // =========================================================================

    function getTimestamp() {
        const now = new Date();
        const pad = (n) => String(n).padStart(2, '0');
        return `[${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}]`;
    }

    function addLog(type, message) {
        const entry = document.createElement('div');
        entry.className = `log-entry log-${type.toLowerCase()}`;

        const timeSpan = document.createElement('span');
        timeSpan.className = 'log-time';
        timeSpan.textContent = getTimestamp();

        const badgeSpan = document.createElement('span');
        badgeSpan.className = `log-badge badge-${type.toLowerCase()}`;
        badgeSpan.textContent = type.toUpperCase();

        const msgSpan = document.createElement('span');
        msgSpan.className = 'log-msg';
        msgSpan.textContent = message;

        entry.appendChild(timeSpan);
        entry.appendChild(badgeSpan);
        entry.appendChild(msgSpan);

        logContainer.appendChild(entry);
        logContainer.scrollTop = logContainer.scrollHeight;
    }

    function showAlert(type, message) {
        connectionAlert.className = `alert alert-${type}`;
        alertMessage.textContent = message;
        connectionAlert.classList.remove('d-none');
    }

    function hideAlert() {
        connectionAlert.classList.add('d-none');
    }

    function formatBytes(bytes) {
        if (bytes === 0 || bytes === undefined || bytes === null) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function sanitizeHTML(str) {
        const temp = document.createElement('div');
        temp.textContent = str;
        return temp.innerHTML;
    }

    // =========================================================================
    // PROTOCOL SELECTOR & SECURITY ADVISORY
    // =========================================================================

    function updateProtocolAdvisory(protocol) {
        currentProtocol = protocol;
        const noticeText = protocolSecurityNotice.querySelector('.notice-text');

        if (protocol === 'sftp') {
            protocolSecurityNotice.className = 'protocol-security-notice notice-secure';
            noticeText.innerHTML = '<strong>Secure Protocol:</strong> SFTP runs over SSH (Port 22) with end-to-end cryptographic encryption and host key verification.';
            portHint.textContent = 'Default SFTP port is 22';
        } else if (protocol === 'ftps') {
            protocolSecurityNotice.className = 'protocol-security-notice notice-secure';
            noticeText.innerHTML = '<strong>Encrypted Protocol:</strong> FTPS secures control commands and file data using TLS/SSL encryption (RFC 4217).';
            portHint.textContent = 'Default FTPS port is 21 (Explicit TLS)';
        } else {
            protocolSecurityNotice.className = 'protocol-security-notice notice-ftp';
            noticeText.innerHTML = '<strong>Security Note:</strong> Standard FTP sends credentials and data in cleartext (RFC 959). For secure communication, choose <strong>FTPS</strong> or <strong>SFTP</strong>.';
            portHint.textContent = 'Default FTP port is 21 (or 2121 for local test)';
        }
    }

    serverProtocolSelect.addEventListener('change', () => {
        const newProto = serverProtocolSelect.value;
        const currentPortVal = serverPortInput.value.trim();

        // Update default port if user hasn't explicitly entered a non-standard port
        if (newProto === 'sftp' && (currentPortVal === '21' || currentPortVal === '2121')) {
            serverPortInput.value = '22';
        } else if ((newProto === 'ftp' || newProto === 'ftps') && currentPortVal === '22') {
            serverPortInput.value = '21';
        }

        updateProtocolAdvisory(newProto);
        addLog('INFO', `Protocol switched to ${newProto.toUpperCase()}.`);
    });

    // =========================================================================
    // UI STATE MANAGEMENT
    // =========================================================================

    function setConnectionState(connected, info = {}) {
        isConnected = connected;

        const navDot = navStatusChip.querySelector('.status-dot');

        if (connected) {
            const protoLabel = (info.protocol || 'FTP').toUpperCase();
            // Navbar chip
            navDot.className = 'status-dot connected';
            navStatusText.textContent = `${protoLabel}: ${info.host || 'Server'}:${info.port || 21}`;

            // Connection card badge
            connectionBadge.className = 'badge-status connected';
            badgeStatusText.textContent = `Connected (${protoLabel})`;

            // Form inputs & buttons
            serverProtocolSelect.disabled = true;
            serverHostInput.disabled = true;
            serverPortInput.disabled = true;
            serverUserInput.disabled = true;
            serverPassInput.disabled = true;
            btnConnect.disabled = true;
            btnTestConnect.disabled = true;
            btnDisconnect.disabled = false;

            // File Manager controls
            btnRefreshFiles.disabled = false;
            btnNewFolder.disabled = false;
            fileUploadInput.disabled = false;
            btnUploadLabel.classList.remove('disabled');

            currentDir = info.current_directory || '/';
            currentDirectoryPath.textContent = currentDir;
            updateParentBtnState();

        } else {
            navDot.className = 'status-dot disconnected';
            navStatusText.textContent = 'Status: Disconnected';

            connectionBadge.className = 'badge-status disconnected';
            badgeStatusText.textContent = 'Disconnected';

            serverProtocolSelect.disabled = false;
            serverHostInput.disabled = false;
            serverPortInput.disabled = false;
            serverUserInput.disabled = false;
            serverPassInput.disabled = false;
            btnConnect.disabled = false;
            btnTestConnect.disabled = false;
            btnDisconnect.disabled = true;

            btnParentDir.disabled = true;
            btnRefreshFiles.disabled = true;
            btnNewFolder.disabled = true;
            fileUploadInput.disabled = true;
            btnUploadLabel.classList.add('disabled');

            currentDir = '/ (Disconnected)';
            currentDirectoryPath.textContent = currentDir;

            renderEmptyTable('No active connection. Connect to an FTP, FTPS, or SFTP server above to view files.');
        }
    }

    function updateParentBtnState() {
        const isRoot = currentDir === '/' || currentDir === '' || currentDir === '\\';
        btnParentDir.disabled = !isConnected || isRoot;
    }

    function renderEmptyTable(message) {
        fileTableBody.innerHTML = `
            <tr class="empty-row">
                <td colspan="5" class="empty-state">
                    <div class="empty-content">
                        <svg viewBox="0 0 24 24" width="38" height="38" fill="none" stroke="#94a3b8" stroke-width="1.5">
                            <rect width="20" height="8" x="2" y="2" rx="2" ry="2"></rect>
                            <rect width="20" height="8" x="2" y="14" rx="2" ry="2"></rect>
                        </svg>
                        <p class="empty-text">${sanitizeHTML(message)}</p>
                        <p class="empty-subtext">Use the toolbar to refresh, upload files, or create folders.</p>
                    </div>
                </td>
            </tr>
        `;
    }

    // =========================================================================
    // HERO & QUICK FILL HELPERS
    // =========================================================================

    if (btnScrollConnect) {
        btnScrollConnect.addEventListener('click', (e) => {
            e.preventDefault();
            const section = document.getElementById('connection-section');
            if (section) {
                section.scrollIntoView({ behavior: 'smooth' });
                serverHostInput.focus();
            }
        });
    }

    if (btnFillDemo) {
        btnFillDemo.addEventListener('click', () => {
            serverProtocolSelect.value = 'ftp';
            updateProtocolAdvisory('ftp');
            serverHostInput.value = '127.0.0.1';
            serverPortInput.value = '2121';
            serverUserInput.value = '';
            serverPassInput.value = '';
            hideAlert();
            addLog('INFO', 'Autofilled local server host (127.0.0.1:2121). Enter your test credentials to connect.');
            const section = document.getElementById('connection-section');
            if (section) {
                section.scrollIntoView({ behavior: 'smooth' });
                serverUserInput.focus();
            }
        });
    }

    // =========================================================================
    // TEST CONNECTION HANDLER
    // =========================================================================

    btnTestConnect.addEventListener('click', async () => {
        hideAlert();

        const host = serverHostInput.value.trim();
        const protocol = serverProtocolSelect.value;
        const port = parseInt(serverPortInput.value, 10) || (protocol === 'sftp' ? 22 : 21);
        const username = serverUserInput.value.trim() || 'anonymous';
        const password = serverPassInput.value;

        if (!host) {
            showAlert('error', 'Please enter a Server IP or Hostname to test.');
            return;
        }

        btnTestConnect.disabled = true;
        testSpinner.classList.remove('d-none');
        addLog('INFO', `Testing ${protocol.toUpperCase()} connection to ${host}:${port}...`);

        try {
            const response = await fetch('/api/test-connect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ host, port, username, password, protocol })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showAlert('success', data.message || 'Connection test successful!');
                addLog('SUCCESS', data.message || `Test connection succeeded on ${protocol.toUpperCase()}`);
            } else {
                showAlert('error', data.message || 'Connection test failed.');
                addLog('ERROR', `Test failed: ${data.message}`);
            }
        } catch (err) {
            showAlert('error', `Connection test request error: ${err.message}`);
            addLog('ERROR', `Test error: ${err.message}`);
        } finally {
            testSpinner.classList.add('d-none');
            if (!isConnected) {
                btnTestConnect.disabled = false;
            }
        }
    });

    // =========================================================================
    // CONNECT & DISCONNECT HANDLERS
    // =========================================================================

    ftpConnectForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideAlert();

        const host = serverHostInput.value.trim();
        const protocol = serverProtocolSelect.value;
        const port = parseInt(serverPortInput.value, 10) || (protocol === 'sftp' ? 22 : 21);
        const username = serverUserInput.value.trim() || 'anonymous';
        const password = serverPassInput.value;

        if (!host) {
            showAlert('error', 'Please enter a valid Server IP or Hostname.');
            return;
        }

        btnConnect.disabled = true;
        btnTestConnect.disabled = true;
        connectSpinner.classList.remove('d-none');
        addLog('INFO', `Connecting to ${host}:${port} via ${protocol.toUpperCase()}...`);

        try {
            const response = await fetch('/api/connect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ host, port, username, password, protocol })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showAlert('success', data.message || 'Connected successfully!');
                addLog('SUCCESS', `Session opened: ${data.message}`);
                setConnectionState(true, {
                    host: data.host,
                    port: data.port,
                    username: data.username,
                    protocol: data.protocol,
                    current_directory: data.current_directory
                });
                await loadFiles();
            } else {
                showAlert('error', data.message || 'Connection failed.');
                addLog('ERROR', `Connection failed: ${data.message}`);
                setConnectionState(false);
            }
        } catch (err) {
            showAlert('error', `Communication error: ${err.message}`);
            addLog('ERROR', `Request error connecting to server: ${err.message}`);
            setConnectionState(false);
        } finally {
            connectSpinner.classList.add('d-none');
            if (!isConnected) {
                btnConnect.disabled = false;
                btnTestConnect.disabled = false;
            }
        }
    });

    btnDisconnect.addEventListener('click', async () => {
        addLog('INFO', 'Terminating session...');
        try {
            const response = await fetch('/api/disconnect', { method: 'POST' });
            const data = await response.json();
            addLog('INFO', data.message || 'Disconnected from server.');
        } catch (err) {
            addLog('INFO', 'Disconnected local session.');
        } finally {
            setConnectionState(false);
            showAlert('success', 'Disconnected from server.');
        }
    });

    // =========================================================================
    // FILE MANAGER OPERATIONS
    // =========================================================================

    async function loadFiles() {
        if (!isConnected) return;

        fileTableBody.innerHTML = `
            <tr>
                <td colspan="5" style="text-align: center; padding: 2rem;">
                    <span class="spinner spinner-sm"></span> Loading remote directory contents...
                </td>
            </tr>
        `;

        try {
            const response = await fetch('/api/files');
            const data = await response.json();

            if (response.ok && data.success) {
                currentDir = data.current_directory || '/';
                currentDirectoryPath.textContent = currentDir;
                updateParentBtnState();

                renderFileList(data.files || []);
                addLog('SUCCESS', `Listed ${data.files.length} items in '${currentDir}'`);
            } else {
                renderEmptyTable(`Failed to list files: ${data.message || 'Unknown error'}`);
                addLog('ERROR', `Failed to list directory contents: ${data.message}`);
            }
        } catch (err) {
            renderEmptyTable(`Error loading files: ${err.message}`);
            addLog('ERROR', `Error requesting file list: ${err.message}`);
        }
    }

    function renderFileList(files) {
        if (!files || files.length === 0) {
            renderEmptyTable('This remote directory is currently empty.');
            return;
        }

        fileTableBody.innerHTML = '';

        files.forEach((item) => {
            const tr = document.createElement('tr');
            const isDir = item.type === 'directory';

            // 1. Icon column
            const iconSvg = isDir
                ? `<svg viewBox="0 0 24 24" width="20" height="20" fill="#f59e0b" stroke="#d97706" stroke-width="1.5">
                     <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"></path>
                   </svg>`
                : `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#64748b" stroke-width="1.8">
                     <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                     <polyline points="14 2 14 8 20 8"></polyline>
                   </svg>`;

            // 2. Name column
            const nameHtml = isDir
                ? `<a href="#" class="folder-link" data-name="${sanitizeHTML(item.name)}">${sanitizeHTML(item.name)}</a>`
                : `<span>${sanitizeHTML(item.name)}</span>`;

            // 3. Type column
            const typeBadge = isDir
                ? `<span class="file-type-badge type-folder">Folder</span>`
                : `<span class="file-type-badge type-file">File</span>`;

            // 4. Size column
            const sizeText = isDir ? '—' : formatBytes(item.size);

            // 5. Actions column
            let actionsHtml = '';
            if (isDir) {
                actionsHtml = `
                    <button type="button" class="btn-table-action btn-open-folder" data-name="${sanitizeHTML(item.name)}" title="Open Folder">
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M5 12h14M12 5l7 7-7 7"/>
                        </svg>
                        Open
                    </button>
                    <button type="button" class="btn-table-action btn-rename" data-name="${sanitizeHTML(item.name)}" data-type="directory" title="Rename Folder">
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 20h9"></path>
                            <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"></path>
                        </svg>
                        Rename
                    </button>
                    <button type="button" class="btn-table-action btn-delete" data-name="${sanitizeHTML(item.name)}" data-type="directory" title="Delete Folder">
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="3 6 5 6 21 6"></polyline>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                        </svg>
                        Delete
                    </button>
                `;
            } else {
                const encodedName = encodeURIComponent(item.name);
                actionsHtml = `
                    <a href="/api/download?filename=${encodedName}" class="btn-table-action btn-download" data-name="${sanitizeHTML(item.name)}" title="Download File">
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="7 10 12 15 17 10"></polyline>
                            <line x1="12" x2="12" y1="15" y2="3"></line>
                        </svg>
                        Download
                    </a>
                    <button type="button" class="btn-table-action btn-rename" data-name="${sanitizeHTML(item.name)}" data-type="file" title="Rename File">
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 20h9"></path>
                            <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"></path>
                        </svg>
                        Rename
                    </button>
                    <button type="button" class="btn-table-action btn-delete" data-name="${sanitizeHTML(item.name)}" data-type="file" title="Delete File">
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="3 6 5 6 21 6"></polyline>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                        </svg>
                        Delete
                    </button>
                `;
            }

            tr.innerHTML = `
                <td>${iconSvg}</td>
                <td><div class="item-name-cell">${nameHtml}</div></td>
                <td>${typeBadge}</td>
                <td><span style="font-family: var(--font-mono); font-size: 0.8rem;">${sizeText}</span></td>
                <td><div class="table-actions">${actionsHtml}</div></td>
            `;

            fileTableBody.appendChild(tr);
        });

        attachTableEventListeners();
    }

    function attachTableEventListeners() {
        document.querySelectorAll('.folder-link, .btn-open-folder').forEach(el => {
            el.addEventListener('click', (e) => {
                e.preventDefault();
                const folderName = el.getAttribute('data-name');
                if (folderName) navigateToFolder(folderName);
            });
        });

        document.querySelectorAll('.btn-download').forEach(el => {
            el.addEventListener('click', () => {
                const fileName = el.getAttribute('data-name');
                addLog('INFO', `Downloading '${fileName}' from remote server...`);
            });
        });

        document.querySelectorAll('.btn-rename').forEach(el => {
            el.addEventListener('click', (e) => {
                e.preventDefault();
                const itemName = el.getAttribute('data-name');
                const itemType = el.getAttribute('data-type');
                openRenameModal(itemName, itemType);
            });
        });

        document.querySelectorAll('.btn-delete').forEach(el => {
            el.addEventListener('click', async (e) => {
                e.preventDefault();
                const itemName = el.getAttribute('data-name');
                const itemType = el.getAttribute('data-type');
                await deleteItem(itemName, itemType);
            });
        });
    }

    async function navigateToFolder(folderName) {
        addLog('INFO', `Navigating into folder '${folderName}'...`);
        try {
            const response = await fetch('/api/cwd', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: folderName, action: 'into' })
            });

            const data = await response.json();
            if (response.ok && data.success) {
                currentDir = data.current_directory || '/';
                currentDirectoryPath.textContent = currentDir;
                updateParentBtnState();
                renderFileList(data.files || []);
                addLog('SUCCESS', `Working directory changed to: ${currentDir}`);
            } else {
                addLog('ERROR', `Cannot enter folder '${folderName}': ${data.message}`);
                showAlert('error', data.message);
            }
        } catch (err) {
            addLog('ERROR', `Navigation error: ${err.message}`);
        }
    }

    btnParentDir.addEventListener('click', async () => {
        addLog('INFO', 'Navigating up to parent folder (..)...');
        try {
            const response = await fetch('/api/cwd', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'parent' })
            });

            const data = await response.json();
            if (response.ok && data.success) {
                currentDir = data.current_directory || '/';
                currentDirectoryPath.textContent = currentDir;
                updateParentBtnState();
                renderFileList(data.files || []);
                addLog('SUCCESS', `Navigated to parent directory: ${currentDir}`);
            } else {
                addLog('ERROR', `Failed to navigate up: ${data.message}`);
            }
        } catch (err) {
            addLog('ERROR', `Error navigating to parent: ${err.message}`);
        }
    });

    btnRefreshFiles.addEventListener('click', () => {
        addLog('INFO', `Refreshing file list for '${currentDir}'...`);
        loadFiles();
    });

    // =========================================================================
    // MODAL OPERATIONS: CREATE FOLDER & RENAME
    // =========================================================================

    // New Folder Modal
    btnNewFolder.addEventListener('click', () => {
        newFolderNameInput.value = '';
        mkdirModal.classList.remove('d-none');
        newFolderNameInput.focus();
    });

    function closeMkdirModal() {
        mkdirModal.classList.add('d-none');
        newFolderNameInput.value = '';
    }

    btnCloseMkdirModal.addEventListener('click', closeMkdirModal);
    btnCancelMkdir.addEventListener('click', closeMkdirModal);

    btnSubmitMkdir.addEventListener('click', async () => {
        const folderName = newFolderNameInput.value.trim();
        if (!folderName) {
            alert('Please enter a folder name.');
            return;
        }

        addLog('INFO', `Creating directory '${folderName}'...`);
        closeMkdirModal();

        try {
            const response = await fetch('/api/mkdir', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ folder_name: folderName })
            });

            const data = await response.json();
            if (response.ok && data.success) {
                addLog('SUCCESS', data.message || `Directory '${folderName}' created.`);
                renderFileList(data.files || []);
            } else {
                addLog('ERROR', `Failed to create folder: ${data.message}`);
                showAlert('error', data.message);
            }
        } catch (err) {
            addLog('ERROR', `Error creating folder: ${err.message}`);
        }
    });

    // Rename Modal
    function openRenameModal(itemName, itemType) {
        renameOldNameInput.value = itemName;
        renameItemTypeInput.value = itemType;
        renameNewNameInput.value = itemName;
        renameModal.classList.remove('d-none');
        renameNewNameInput.focus();
        renameNewNameInput.select();
    }

    function closeRenameModal() {
        renameModal.classList.add('d-none');
        renameOldNameInput.value = '';
        renameNewNameInput.value = '';
    }

    btnCloseRenameModal.addEventListener('click', closeRenameModal);
    btnCancelRename.addEventListener('click', closeRenameModal);

    btnSubmitRename.addEventListener('click', async () => {
        const oldName = renameOldNameInput.value.trim();
        const newName = renameNewNameInput.value.trim();
        const itemType = renameItemTypeInput.value;

        if (!newName) {
            alert('Please enter a valid new name.');
            return;
        }

        if (oldName === newName) {
            closeRenameModal();
            return;
        }

        addLog('INFO', `Renaming '${oldName}' to '${newName}'...`);
        closeRenameModal();

        try {
            const response = await fetch('/api/rename', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ old_name: oldName, new_name: newName, type: itemType })
            });

            const data = await response.json();
            if (response.ok && data.success) {
                addLog('SUCCESS', data.message || `Renamed '${oldName}' to '${newName}'.`);
                renderFileList(data.files || []);
            } else {
                addLog('ERROR', `Rename failed: ${data.message}`);
                showAlert('error', data.message);
            }
        } catch (err) {
            addLog('ERROR', `Error renaming item: ${err.message}`);
        }
    });

    // =========================================================================
    // FILE UPLOAD WITH PROGRESS TRACKING
    // =========================================================================

    fileUploadInput.addEventListener('change', () => {
        if (!fileUploadInput.files || fileUploadInput.files.length === 0) return;

        const file = fileUploadInput.files[0];
        const formData = new FormData();
        formData.append('file', file);

        uploadFileName.textContent = `Uploading "${file.name}" (${formatBytes(file.size)})...`;
        uploadPercent.textContent = '0%';
        uploadProgressBarFill.style.width = '0%';
        uploadProgressBox.classList.remove('d-none');
        btnUploadLabel.classList.add('disabled');
        fileUploadInput.disabled = true;

        addLog('INFO', `Uploading '${file.name}' (${formatBytes(file.size)})...`);

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload', true);

        // Upload progress listener
        xhr.upload.onprogress = (e) => {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 100);
                uploadProgressBarFill.style.width = `${percent}%`;
                uploadPercent.textContent = `${percent}%`;
            }
        };

        xhr.onload = async () => {
            uploadProgressBox.classList.add('d-none');
            btnUploadLabel.classList.remove('disabled');
            fileUploadInput.disabled = false;
            fileUploadInput.value = '';

            try {
                const data = JSON.parse(xhr.responseText);
                if (xhr.status === 200 && data.success) {
                    addLog('SUCCESS', data.message || `File '${file.name}' uploaded successfully.`);
                    showAlert('success', `File '${file.name}' uploaded successfully!`);
                    await loadFiles();
                } else {
                    addLog('ERROR', `Upload failed for '${file.name}': ${data.message}`);
                    showAlert('error', data.message || 'File upload failed.');
                }
            } catch (e) {
                addLog('ERROR', `Error parsing server upload response.`);
            }
        };

        xhr.onerror = () => {
            uploadProgressBox.classList.add('d-none');
            btnUploadLabel.classList.remove('disabled');
            fileUploadInput.disabled = false;
            fileUploadInput.value = '';
            addLog('ERROR', `Network error during upload of '${file.name}'.`);
            showAlert('error', 'Network error during upload.');
        };

        xhr.send(formData);
    });

    // =========================================================================
    // ITEM DELETION
    // =========================================================================

    async function deleteItem(itemName, itemType) {
        const isDir = itemType === 'directory';
        const confirmMsg = isDir
            ? `Are you sure you want to delete the directory "${itemName}"? (Must be empty)`
            : `Are you sure you want to delete the file "${itemName}"?`;

        if (!confirm(confirmMsg)) return;

        addLog('INFO', `Deleting ${itemType} '${itemName}'...`);

        try {
            const response = await fetch('/api/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: itemName, type: itemType })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                addLog('SUCCESS', data.message || `Successfully removed '${itemName}'.`);
                await loadFiles();
            } else {
                addLog('ERROR', `Failed to delete '${itemName}': ${data.message}`);
                showAlert('error', data.message || 'Delete operation failed.');
            }
        } catch (err) {
            addLog('ERROR', `Delete request error: ${err.message}`);
        }
    }

    // =========================================================================
    // ACTIVITY LOG CONTROLS
    // =========================================================================

    btnClearLogs.addEventListener('click', () => {
        logContainer.innerHTML = '';
        addLog('INFO', 'Activity log cleared by user.');
    });

    // Initial state setup
    updateProtocolAdvisory('ftp');
    setConnectionState(false);
});
