/**
 * app.js
 * Frontend controller for NetTransfer – Multi-Protocol File Transfer System (FTP, FTPS, SFTP)
 * Includes Client Registration, Secure Authentication, Automatic FTP Account Provisioning,
 * and Multi-Tenant Isolated Storage Management.
 * Course: Computer Networks and Ethical Hacking
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements - Navigation & Auth Controls
    const navGuestGroup = document.getElementById('navGuestGroup');
    const navUserGroup = document.getElementById('navUserGroup');
    const navUsernameDisplay = document.getElementById('navUsernameDisplay');
    const btnNavLogin = document.getElementById('btnNavLogin');
    const btnNavRegister = document.getElementById('btnNavRegister');
    const btnNavLogout = document.getElementById('btnNavLogout');
    const btnHeroCreateAccount = document.getElementById('btnHeroCreateAccount');
    const authNoticeBanner = document.getElementById('authNoticeBanner');
    const authBannerText = document.getElementById('authBannerText');
    const btnFillMyAccount = document.getElementById('btnFillMyAccount');

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

    // DOM Elements - Register Modal
    const registerModal = document.getElementById('registerModal');
    const registerForm = document.getElementById('registerForm');
    const registerAlert = document.getElementById('registerAlert');
    const regFullName = document.getElementById('regFullName');
    const regEmail = document.getElementById('regEmail');
    const regUsername = document.getElementById('regUsername');
    const regPassword = document.getElementById('regPassword');
    const regConfirmPassword = document.getElementById('regConfirmPassword');
    const btnCloseRegisterModal = document.getElementById('btnCloseRegisterModal');
    const btnCancelRegister = document.getElementById('btnCancelRegister');
    const btnSubmitRegister = document.getElementById('btnSubmitRegister');
    const registerSpinner = document.getElementById('registerSpinner');
    const linkSwitchToLogin = document.getElementById('linkSwitchToLogin');

    // DOM Elements - Login Modal
    const loginModal = document.getElementById('loginModal');
    const loginForm = document.getElementById('loginForm');
    const loginAlert = document.getElementById('loginAlert');
    const loginIdentifier = document.getElementById('loginIdentifier');
    const loginPassword = document.getElementById('loginPassword');
    const btnCloseLoginModal = document.getElementById('btnCloseLoginModal');
    const btnCancelLogin = document.getElementById('btnCancelLogin');
    const btnSubmitLogin = document.getElementById('btnSubmitLogin');
    const loginSpinner = document.getElementById('loginSpinner');
    const linkSwitchToRegister = document.getElementById('linkSwitchToRegister');

    // DOM Elements - Folder Creation Modal
    const mkdirModal = document.getElementById('mkdirModal');
    const newFolderNameInput = document.getElementById('newFolderName');
    const btnCloseMkdirModal = document.getElementById('btnCloseMkdirModal');
    const btnCancelMkdir = document.getElementById('btnCancelMkdir');
    const btnSubmitMkdir = document.getElementById('btnSubmitMkdir');

    // DOM Elements - Rename Modal
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
    let currentUser = null;

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
        temp.textContent = str || '';
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
            noticeText.innerHTML = '<strong>Security Warning:</strong> Standard FTP transmits credentials and files in cleartext over the network (RFC 959). For encrypted transmission, select <strong>FTPS</strong> or <strong>SFTP</strong>.';
            portHint.textContent = 'Default FTP port is 21 (or 2121 for local test)';
        }
    }

    serverProtocolSelect.addEventListener('change', () => {
        const newProto = serverProtocolSelect.value;
        const currentPortVal = serverPortInput.value.trim();

        if (newProto === 'sftp' && (currentPortVal === '21' || currentPortVal === '2121')) {
            serverPortInput.value = '22';
        } else if ((newProto === 'ftp' || newProto === 'ftps') && currentPortVal === '22') {
            serverPortInput.value = '2121';
        }

        updateProtocolAdvisory(newProto);
        addLog('INFO', `Protocol switched to ${newProto.toUpperCase()}.`);
    });

    // =========================================================================
    // AUTHENTICATION & SESSION STATE MANAGEMENT
    // =========================================================================

    function renderAuthState() {
        if (currentUser) {
            // User is authenticated
            navGuestGroup.classList.add('d-none');
            navUserGroup.classList.remove('d-none');
            navUsernameDisplay.textContent = currentUser.username;

            authNoticeBanner.className = 'auth-notice-banner user-mode';
            authBannerText.innerHTML = `<strong>Logged in as ${sanitizeHTML(currentUser.fullname)} (${sanitizeHTML(currentUser.username)})</strong>. Your FTP account is active with isolated storage chrooted to <code>users/${sanitizeHTML(currentUser.username)}</code>.`;

            // Auto-fill username in form if empty or changed
            if (!serverUserInput.value || serverUserInput.value === 'anonymous') {
                serverUserInput.value = currentUser.username;
            }
        } else {
            // Guest mode
            navGuestGroup.classList.remove('d-none');
            navUserGroup.classList.add('d-none');

            authNoticeBanner.className = 'auth-notice-banner guest-mode';
            authBannerText.innerHTML = `<strong>Client Account Required:</strong> Please <a href="javascript:void(0)" id="linkBannerLogin">Log In</a> or <a href="javascript:void(0)" id="linkBannerRegister">Create an Account</a>. Your FTP account and isolated storage directory will be automatically provisioned!`;

            // Bind dynamic links inside banner
            const linkLogin = document.getElementById('linkBannerLogin');
            const linkReg = document.getElementById('linkBannerRegister');
            if (linkLogin) linkLogin.onclick = openLoginModal;
            if (linkReg) linkReg.onclick = openRegisterModal;
        }
    }

    async function checkCurrentSession() {
        try {
            const res = await fetch('/api/me');
            const data = await res.json();
            if (data.authenticated && data.user) {
                currentUser = data.user;
                addLog('INFO', `Session restored: Welcome back, ${currentUser.username}.`);
            } else {
                currentUser = null;
            }
        } catch (err) {
            currentUser = null;
        }
        renderAuthState();
    }

    // Modal Control Functions
    function openRegisterModal() {
        registerAlert.classList.add('d-none');
        registerModal.classList.remove('d-none');
        regFullName.focus();
    }

    function closeRegisterModal() {
        registerModal.classList.add('d-none');
        registerForm.reset();
    }

    function openLoginModal() {
        loginAlert.classList.add('d-none');
        loginModal.classList.remove('d-none');
        loginIdentifier.focus();
    }

    function closeLoginModal() {
        loginModal.classList.add('d-none');
        loginForm.reset();
    }

    // Modal Triggers
    if (btnNavRegister) btnNavRegister.onclick = openRegisterModal;
    if (btnNavLogin) btnNavLogin.onclick = openLoginModal;
    if (btnHeroCreateAccount) btnHeroCreateAccount.onclick = openRegisterModal;
    if (btnCloseRegisterModal) btnCloseRegisterModal.onclick = closeRegisterModal;
    if (btnCancelRegister) btnCancelRegister.onclick = closeRegisterModal;
    if (btnCloseLoginModal) btnCloseLoginModal.onclick = closeLoginModal;
    if (btnCancelLogin) btnCancelLogin.onclick = closeLoginModal;

    if (linkSwitchToLogin) {
        linkSwitchToLogin.onclick = () => {
            closeRegisterModal();
            openLoginModal();
        };
    }

    if (linkSwitchToRegister) {
        linkSwitchToRegister.onclick = () => {
            closeLoginModal();
            openRegisterModal();
        };
    }

    // Registration Form Submission
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        registerAlert.classList.add('d-none');

        const fullname = regFullName.value.trim();
        const email = regEmail.value.trim();
        const username = regUsername.value.trim();
        const password = regPassword.value;
        const confirm_password = regConfirmPassword.value;

        if (password !== confirm_password) {
            registerAlert.className = 'alert alert-error';
            registerAlert.textContent = 'Passwords do not match.';
            registerAlert.classList.remove('d-none');
            return;
        }

        btnSubmitRegister.disabled = true;
        registerSpinner.classList.remove('d-none');

        try {
            const res = await fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    fullname,
                    email,
                    username,
                    password,
                    confirm_password
                })
            });
            const data = await res.json();

            if (res.ok && data.success) {
                currentUser = data.user;
                closeRegisterModal();
                renderAuthState();
                serverUserInput.value = currentUser.username;
                serverPassInput.value = password;
                addLog('SUCCESS', `Client account registered and FTP storage provisioned for '${currentUser.username}'.`);
                showAlert('success', `Account created! Your FTP storage is ready. You are now logged in as ${currentUser.username}.`);
            } else {
                registerAlert.className = 'alert alert-error';
                registerAlert.textContent = data.message || 'Registration failed.';
                registerAlert.classList.remove('d-none');
                addLog('ERROR', `Registration failed: ${data.message}`);
            }
        } catch (err) {
            registerAlert.className = 'alert alert-error';
            registerAlert.textContent = `Network error: ${err.message}`;
            registerAlert.classList.remove('d-none');
        } finally {
            btnSubmitRegister.disabled = false;
            registerSpinner.classList.add('d-none');
        }
    });

    // Login Form Submission
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginAlert.classList.add('d-none');

        const identifier = loginIdentifier.value.trim();
        const password = loginPassword.value;

        btnSubmitLogin.disabled = true;
        loginSpinner.classList.remove('d-none');

        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identifier, password })
            });
            const data = await res.json();

            if (res.ok && data.success) {
                currentUser = data.user;
                closeLoginModal();
                renderAuthState();
                serverUserInput.value = currentUser.username;
                serverPassInput.value = password;
                addLog('SUCCESS', `Client '${currentUser.username}' logged in successfully.`);
                showAlert('success', `Welcome back, ${currentUser.fullname}! You can now connect to your FTP storage.`);
            } else {
                loginAlert.className = 'alert alert-error';
                loginAlert.textContent = data.message || 'Login failed.';
                loginAlert.classList.remove('d-none');
                addLog('ERROR', `Login failed: ${data.message}`);
            }
        } catch (err) {
            loginAlert.className = 'alert alert-error';
            loginAlert.textContent = `Network error: ${err.message}`;
            loginAlert.classList.remove('d-none');
        } finally {
            btnSubmitLogin.disabled = false;
            loginSpinner.classList.add('d-none');
        }
    });

    // Logout Button
    btnNavLogout.addEventListener('click', async () => {
        try {
            await fetch('/api/logout', { method: 'POST' });
            setConnectionState(false);
            currentUser = null;
            renderAuthState();
            serverPassInput.value = '';
            addLog('INFO', 'Client logged out. Session terminated.');
            showAlert('info', 'You have been logged out.');
        } catch (err) {
            addLog('ERROR', `Logout error: ${err.message}`);
        }
    });

    // Autofill My Account Button
    btnFillMyAccount.addEventListener('click', () => {
        if (!currentUser) {
            showAlert('warning', 'Please Log In or Create an Account first.');
            openLoginModal();
            return;
        }
        serverProtocolSelect.value = 'ftp';
        serverHostInput.value = '127.0.0.1';
        serverPortInput.value = '2121';
        serverUserInput.value = currentUser.username;
        serverPassInput.focus();
        updateProtocolAdvisory('ftp');
        addLog('INFO', `Autofilled connection details for registered client '${currentUser.username}'.`);
    });

    // =========================================================================
    // UI CONNECTION STATE MANAGEMENT
    // =========================================================================

    function setConnectionState(connected, info = {}) {
        isConnected = connected;

        const navDot = navStatusChip.querySelector('.status-dot');

        if (connected) {
            const protoLabel = (info.protocol || 'FTP').toUpperCase();
            navDot.className = 'status-dot connected';
            navStatusText.textContent = `${protoLabel}: ${info.host || 'Server'}:${info.port || 21}`;

            connectionBadge.className = 'badge-status connected';
            badgeStatusText.textContent = `Connected (${protoLabel})`;

            serverProtocolSelect.disabled = true;
            serverHostInput.disabled = true;
            serverPortInput.disabled = true;
            serverUserInput.disabled = true;
            serverPassInput.disabled = true;
            btnConnect.disabled = true;
            btnTestConnect.disabled = true;
            btnDisconnect.disabled = false;

            btnRefreshFiles.disabled = false;
            btnNewFolder.disabled = false;
            fileUploadInput.disabled = false;
            btnUploadLabel.classList.remove('disabled');
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

            currentDir = '/';
            currentDirectoryPath.textContent = '/ (Disconnected)';
            renderEmptyFileList('No active connection.', 'Connect to your FTP storage above to view and transfer files.');
        }
    }

    // =========================================================================
    // FILE LIST RENDERING
    // =========================================================================

    function renderEmptyFileList(title, subtitle) {
        fileTableBody.innerHTML = `
            <tr class="empty-row">
                <td colspan="5" class="empty-state">
                    <div class="empty-content">
                        <svg viewBox="0 0 24 24" width="40" height="40" fill="none" stroke="#94a3b8" stroke-width="1.5">
                            <rect width="20" height="8" x="2" y="2" rx="2" ry="2"></rect>
                            <rect width="20" height="8" x="2" y="14" rx="2" ry="2"></rect>
                        </svg>
                        <p class="empty-text">${sanitizeHTML(title)}</p>
                        <p class="empty-subtext">${sanitizeHTML(subtitle)}</p>
                    </div>
                </td>
            </tr>
        `;
    }

    function renderFileList(files) {
        if (!files || files.length === 0) {
            renderEmptyFileList('This folder is currently empty.', 'Upload files or create subfolders using the toolbar buttons above.');
            return;
        }

        files.sort((a, b) => {
            if (a.is_dir && !b.is_dir) return -1;
            if (!a.is_dir && b.is_dir) return 1;
            return a.name.localeCompare(b.name);
        });

        fileTableBody.innerHTML = '';

        files.forEach((item) => {
            const tr = document.createElement('tr');

            const iconHtml = item.is_dir
                ? `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#eab308" stroke-width="2"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"></path></svg>`
                : `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#64748b" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>`;

            const nameHtml = item.is_dir
                ? `<a class="folder-link" data-folder="${sanitizeHTML(item.name)}">${sanitizeHTML(item.name)}</a>`
                : `<span>${sanitizeHTML(item.name)}</span>`;

            const kindBadge = item.is_dir
                ? `<span class="file-type-badge badge-dir">Directory</span>`
                : `<span class="file-type-badge badge-file">File</span>`;

            const sizeText = item.is_dir ? '—' : formatBytes(item.size);

            let actionButtons = `
                <div class="action-buttons-group">
                    <button type="button" class="btn btn-sm btn-outline btn-rename" data-name="${sanitizeHTML(item.name)}" data-type="${item.is_dir ? 'directory' : 'file'}" title="Rename">
                        Rename
                    </button>
                    <button type="button" class="btn btn-sm btn-danger btn-delete" data-name="${sanitizeHTML(item.name)}" data-type="${item.is_dir ? 'directory' : 'file'}" title="Delete">
                        Delete
                    </button>
            `;

            if (item.is_dir) {
                actionButtons = `
                    <div class="action-buttons-group">
                        <button type="button" class="btn btn-sm btn-primary btn-open-dir" data-folder="${sanitizeHTML(item.name)}" title="Open Folder">
                            Open
                        </button>
                        <button type="button" class="btn btn-sm btn-outline btn-rename" data-name="${sanitizeHTML(item.name)}" data-type="directory" title="Rename">
                            Rename
                        </button>
                        <button type="button" class="btn btn-sm btn-danger btn-delete" data-name="${sanitizeHTML(item.name)}" data-type="directory" title="Delete">
                            Delete
                        </button>
                    </div>
                `;
            } else {
                actionButtons = `
                    <div class="action-buttons-group">
                        <button type="button" class="btn btn-sm btn-outline btn-download" data-file="${sanitizeHTML(item.name)}" title="Download File">
                            Download
                        </button>
                        <button type="button" class="btn btn-sm btn-outline btn-rename" data-name="${sanitizeHTML(item.name)}" data-type="file" title="Rename">
                            Rename
                        </button>
                        <button type="button" class="btn btn-sm btn-danger btn-delete" data-name="${sanitizeHTML(item.name)}" data-type="file" title="Delete">
                            Delete
                        </button>
                    </div>
                `;
            }

            tr.innerHTML = `
                <td>${iconHtml}</td>
                <td class="item-name-cell">${nameHtml}</td>
                <td>${kindBadge}</td>
                <td>${sizeText}</td>
                <td style="text-align: right;">${actionButtons}</td>
            `;

            fileTableBody.appendChild(tr);
        });

        // Attach action handlers
        fileTableBody.querySelectorAll('.folder-link, .btn-open-dir').forEach((el) => {
            el.addEventListener('click', (e) => {
                const folder = e.currentTarget.getAttribute('data-folder');
                changeDirectory(folder, 'into');
            });
        });

        fileTableBody.querySelectorAll('.btn-download').forEach((el) => {
            el.addEventListener('click', (e) => {
                const filename = e.currentTarget.getAttribute('data-file');
                downloadFile(filename);
            });
        });

        fileTableBody.querySelectorAll('.btn-rename').forEach((el) => {
            el.addEventListener('click', (e) => {
                const name = e.currentTarget.getAttribute('data-name');
                const type = e.currentTarget.getAttribute('data-type');
                openRenameModal(name, type);
            });
        });

        fileTableBody.querySelectorAll('.btn-delete').forEach((el) => {
            el.addEventListener('click', (e) => {
                const name = e.currentTarget.getAttribute('data-name');
                const type = e.currentTarget.getAttribute('data-type');
                deleteItem(name, type);
            });
        });
    }

    // =========================================================================
    // API OPERATIONS: LOAD FILES & NAVIGATION
    // =========================================================================

    async function loadFiles() {
        if (!isConnected) return;

        addLog('INFO', `Requesting directory listing for '${currentDir}'...`);

        try {
            const response = await fetch('/api/files');
            const data = await response.json();

            if (response.ok && data.success) {
                currentDir = data.current_directory || '/';
                currentDirectoryPath.textContent = currentDir;
                btnParentDir.disabled = (currentDir === '/' || currentDir === '');
                renderFileList(data.files);
                addLog('SUCCESS', `Directory listing received (${data.files.length} items).`);
            } else {
                addLog('ERROR', `Failed to load files: ${data.message}`);
                showAlert('error', data.message || 'Error loading directory contents.');
            }
        } catch (err) {
            addLog('ERROR', `Network error while fetching files: ${err.message}`);
            showAlert('error', 'Network error while fetching file list.');
        }
    }

    async function changeDirectory(targetPath, action = 'into') {
        if (!isConnected) return;

        addLog('INFO', action === 'parent' ? 'Navigating to parent directory...' : `Navigating into '${targetPath}'...`);

        try {
            const response = await fetch('/api/cwd', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: targetPath, action: action })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                currentDir = data.current_directory || '/';
                currentDirectoryPath.textContent = currentDir;
                btnParentDir.disabled = (currentDir === '/' || currentDir === '');
                renderFileList(data.files);
                addLog('SUCCESS', `Directory changed to '${currentDir}'.`);
            } else {
                addLog('ERROR', `Directory navigation failed: ${data.message}`);
                showAlert('error', data.message || 'Could not change directory.');
            }
        } catch (err) {
            addLog('ERROR', `Network error during directory change: ${err.message}`);
        }
    }

    btnParentDir.addEventListener('click', () => {
        changeDirectory('', 'parent');
    });

    btnRefreshFiles.addEventListener('click', () => {
        loadFiles();
    });

    // =========================================================================
    // CONNECTION CONTROLS (CONNECT, TEST, DISCONNECT)
    // =========================================================================

    btnFillDemo.addEventListener('click', () => {
        serverProtocolSelect.value = 'ftp';
        serverHostInput.value = '127.0.0.1';
        serverPortInput.value = '2121';
        if (currentUser) {
            serverUserInput.value = currentUser.username;
        } else {
            serverUserInput.value = 'student';
            serverPassInput.value = 'student123';
        }
        updateProtocolAdvisory('ftp');
        addLog('INFO', 'Autofilled local authorized test server configuration (127.0.0.1:2121).');
    });

    btnTestConnect.addEventListener('click', async () => {
        if (!currentUser) {
            showAlert('warning', 'Please Log In or Create an Account first.');
            openLoginModal();
            return;
        }

        hideAlert();
        const protocol = serverProtocolSelect.value;
        const host = serverHostInput.value.trim();
        const port = parseInt(serverPortInput.value.trim(), 10);
        const username = serverUserInput.value.trim();
        const password = serverPassInput.value;

        if (!host) {
            showAlert('error', 'Please provide a valid server hostname or IP address.');
            return;
        }

        btnTestConnect.disabled = true;
        testSpinner.classList.remove('d-none');
        addLog('INFO', `Testing ${protocol.toUpperCase()} connection to ${host}:${port} for user '${username}'...`);

        try {
            const response = await fetch('/api/test-connect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ protocol, host, port, username, password })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showAlert('success', data.message || 'Connection test succeeded! Remote host is reachable.');
                addLog('SUCCESS', data.message);
            } else {
                showAlert('error', data.message || 'Connection test failed.');
                addLog('ERROR', data.message || 'Handshake failed.');
            }
        } catch (err) {
            showAlert('error', `Connection test error: ${err.message}`);
            addLog('ERROR', `Test connection failed: ${err.message}`);
        } finally {
            btnTestConnect.disabled = false;
            testSpinner.classList.add('d-none');
        }
    });

    ftpConnectForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!currentUser) {
            showAlert('warning', 'Please Log In or Create an Account first.');
            openLoginModal();
            return;
        }

        hideAlert();

        const protocol = serverProtocolSelect.value;
        const host = serverHostInput.value.trim();
        const port = parseInt(serverPortInput.value.trim(), 10);
        const username = serverUserInput.value.trim();
        const password = serverPassInput.value;

        if (!host) {
            showAlert('error', 'Please provide a valid server hostname or IP address.');
            return;
        }

        btnConnect.disabled = true;
        connectSpinner.classList.remove('d-none');
        addLog('INFO', `Initiating ${protocol.toUpperCase()} control socket to ${host}:${port}...`);

        try {
            const response = await fetch('/api/connect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ protocol, host, port, username, password })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                setConnectionState(true, {
                    host: data.host,
                    port: data.port,
                    username: data.username,
                    protocol: data.protocol
                });

                showAlert('success', data.message || 'Connected successfully.');
                addLog('SUCCESS', data.message || `Connected to ${data.host} (${data.protocol.toUpperCase()}).`);

                await loadFiles();
            } else {
                showAlert('error', data.message || 'Failed to connect.');
                addLog('ERROR', data.message || 'Connection handshake failed.');
            }
        } catch (err) {
            showAlert('error', `Network error during connection: ${err.message}`);
            addLog('ERROR', `Connection request error: ${err.message}`);
        } finally {
            btnConnect.disabled = isConnected;
            connectSpinner.classList.add('d-none');
        }
    });

    btnDisconnect.addEventListener('click', async () => {
        addLog('INFO', 'Sending disconnect request...');

        try {
            const response = await fetch('/api/disconnect', { method: 'POST' });
            const data = await response.json();

            setConnectionState(false);
            showAlert('info', data.message || 'Disconnected from server.');
            addLog('SUCCESS', 'Session terminated. Sockets closed.');
        } catch (err) {
            setConnectionState(false);
            addLog('ERROR', `Disconnect error: ${err.message}`);
        }
    });

    // =========================================================================
    // FOLDER CREATION (MKDIR)
    // =========================================================================

    function openMkdirModal() {
        newFolderNameInput.value = '';
        mkdirModal.classList.remove('d-none');
        newFolderNameInput.focus();
    }

    function closeMkdirModal() {
        mkdirModal.classList.add('d-none');
    }

    btnNewFolder.addEventListener('click', openMkdirModal);
    btnCloseMkdirModal.addEventListener('click', closeMkdirModal);
    btnCancelMkdir.addEventListener('click', closeMkdirModal);

    btnSubmitMkdir.addEventListener('click', async () => {
        const folderName = newFolderNameInput.value.trim();
        if (!folderName) {
            alert('Please enter a folder name.');
            return;
        }

        btnSubmitMkdir.disabled = true;
        addLog('INFO', `Creating folder '${folderName}'...`);

        try {
            const response = await fetch('/api/mkdir', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ folder_name: folderName })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                closeMkdirModal();
                addLog('SUCCESS', data.message || `Folder '${folderName}' created.`);
                renderFileList(data.files);
            } else {
                addLog('ERROR', `Failed to create folder: ${data.message}`);
                alert(`Error: ${data.message}`);
            }
        } catch (err) {
            addLog('ERROR', `Network error creating folder: ${err.message}`);
        } finally {
            btnSubmitMkdir.disabled = false;
        }
    });

    // =========================================================================
    // ITEM RENAMING
    // =========================================================================

    function openRenameModal(oldName, itemType) {
        renameOldNameInput.value = oldName;
        renameItemTypeInput.value = itemType;
        renameNewNameInput.value = oldName;
        renameModal.classList.remove('d-none');
        renameNewNameInput.focus();
        renameNewNameInput.select();
    }

    function closeRenameModal() {
        renameModal.classList.add('d-none');
    }

    btnCloseRenameModal.addEventListener('click', closeRenameModal);
    btnCancelRename.addEventListener('click', closeRenameModal);

    btnSubmitRename.addEventListener('click', async () => {
        const oldName = renameOldNameInput.value;
        const newName = renameNewNameInput.value.trim();
        const itemType = renameItemTypeInput.value;

        if (!newName) {
            alert('Please enter a new name.');
            return;
        }

        if (oldName === newName) {
            closeRenameModal();
            return;
        }

        btnSubmitRename.disabled = true;
        addLog('INFO', `Renaming '${oldName}' to '${newName}'...`);

        try {
            const response = await fetch('/api/rename', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ old_name: oldName, new_name: newName, type: itemType })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                closeRenameModal();
                addLog('SUCCESS', data.message || `Successfully renamed to '${newName}'.`);
                renderFileList(data.files);
            } else {
                addLog('ERROR', `Rename failed: ${data.message}`);
                alert(`Error: ${data.message}`);
            }
        } catch (err) {
            addLog('ERROR', `Network error during rename: ${err.message}`);
        } finally {
            btnSubmitRename.disabled = false;
        }
    });

    // =========================================================================
    // FILE DOWNLOAD
    // =========================================================================

    function downloadFile(filename) {
        addLog('INFO', `Starting download for '${filename}'...`);
        const downloadUrl = `/api/download?filename=${encodeURIComponent(filename)}`;

        const hiddenAnchor = document.createElement('a');
        hiddenAnchor.href = downloadUrl;
        hiddenAnchor.download = filename;
        document.body.appendChild(hiddenAnchor);
        hiddenAnchor.click();
        document.body.removeChild(hiddenAnchor);

        addLog('SUCCESS', `Download initiated for '${filename}'.`);
    }

    // =========================================================================
    // FILE UPLOAD (WITH LIVE PROGRESS INDICATOR)
    // =========================================================================

    fileUploadInput.addEventListener('change', () => {
        if (!fileUploadInput.files || fileUploadInput.files.length === 0) return;

        const file = fileUploadInput.files[0];

        // 50 MB Client-Side Limit Check
        if (file.size > 50 * 1024 * 1024) {
            showAlert('error', 'File size exceeds maximum permitted limit (50 MB).');
            fileUploadInput.value = '';
            return;
        }

        addLog('INFO', `Initiating upload for '${file.name}' (${formatBytes(file.size)})...`);

        uploadFileName.textContent = `Uploading: ${file.name} (${formatBytes(file.size)})`;
        uploadPercent.textContent = '0%';
        uploadProgressBarFill.style.width = '0%';
        uploadProgressBox.classList.remove('d-none');

        btnUploadLabel.classList.add('disabled');
        fileUploadInput.disabled = true;

        const formData = new FormData();
        formData.append('file', file);

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload', true);

        xhr.upload.onprogress = (e) => {
            if (e.lengthComputable) {
                const percentComplete = Math.round((e.loaded / e.total) * 100);
                uploadPercent.textContent = `${percentComplete}%`;
                uploadProgressBarFill.style.width = `${percentComplete}%`;
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
                    showAlert('success', `File '${file.name}' uploaded successfully.`);
                    await loadFiles();
                } else {
                    addLog('ERROR', `Upload rejected: ${data.message}`);
                    showAlert('error', data.message || 'File upload failed.');
                }
            } catch (err) {
                addLog('ERROR', `Failed to parse upload response: ${err.message}`);
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

    // Initial setup
    updateProtocolAdvisory('ftp');
    setConnectionState(false);
    checkCurrentSession();
});
