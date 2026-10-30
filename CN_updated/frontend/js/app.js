/**
 * Main Application Orchestrator & WebSocket Manager
 */

const App = {
    ws: null,
    wsReconnectTimeout: null,
    pingInterval: null,
    incomingMessageQueue: Promise.resolve(),

    async init() {
        this.bindAuthEvents();
        this.bindChatEvents();

        const user = await window.Auth.checkAuth();
        if (user) {
            this.showChatView(user.username);
        } else {
            this.showAuthView();
        }
    },

    showAuthView() {
        document.getElementById('auth-view').style.display = 'flex';
        document.getElementById('chat-view').style.display = 'none';
        this.stopWebSocket();
    },

    async showChatView(username) {
        document.getElementById('auth-view').style.display = 'none';
        document.getElementById('chat-view').style.display = 'flex';
        document.getElementById('current-username-display').textContent = username;

        await window.Chat.init();
        this.startWebSocket();
    },

    startWebSocket() {
        const token = window.Auth.getToken();
        if (!token) return;

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;

        this.setWsStatus('connecting');

        this.ws = new WebSocket(wsUrl, ['cypherchat', `bearer.${token}`]);

        this.ws.onopen = () => {
            console.log('WebSocket connected successfully');
            this.setWsStatus('connected');
            window.Chat.loadContacts();
            // Keepalive ping every 25 seconds
            clearInterval(this.pingInterval);
            this.pingInterval = setInterval(() => {
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(JSON.stringify({ type: 'ping' }));
                }
            }, 25000);
        };

        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.incomingMessageQueue = this.incomingMessageQueue
                    .then(() => this.handleWebSocketEvent(data))
                    .catch((err) => console.error('Error handling WebSocket message:', err));
            } catch (err) {
                console.error('Error handling WebSocket message:', err);
            }
        };

        this.ws.onclose = (event) => {
            console.warn('WebSocket closed:', event.code, event.reason);
            this.setWsStatus('disconnected');
            clearInterval(this.pingInterval);
            // Reconnect after 3 seconds
            clearTimeout(this.wsReconnectTimeout);
            this.wsReconnectTimeout = setTimeout(() => {
                if (window.Auth.getToken()) {
                    this.startWebSocket();
                }
            }, 3000);
        };

        this.ws.onerror = (err) => {
            console.error('WebSocket error:', err);
        };
    },

    stopWebSocket() {
        clearInterval(this.pingInterval);
        clearTimeout(this.wsReconnectTimeout);
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    },

    sendWebSocketMessage(obj) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(obj));
            return true;
        } else {
            console.warn('WebSocket not connected. Message queued or dropped.');
            return false;
        }
    },

    async handleWebSocketEvent(data) {
        switch (data.type) {
            case 'initial_sync':
                await window.Chat.loadContacts();
                window.Chat.syncOnlineUsers(data.online_users || []);
                break;
            case 'user_status':
                await window.Chat.updateUserStatus(data.username, data.status);
                break;
            case 'encrypted_message':
                await window.Chat.handleIncomingMessage(data.payload);
                break;
            case 'message_ack':
                window.Chat.handleMessageAck(data);
                break;
            case 'error': {
                const error = document.getElementById('chat-error-msg');
                if (error) error.textContent = data.message || 'The server rejected the message.';
                window.Chat.handleServerError(data);
                break;
            }
            case 'pong':
                // Ping acknowledged
                break;
            case 'receipt_ack':
                break;
            default:
                console.log('Unhandled WebSocket event:', data);
        }
    },

    setWsStatus(status) {
        const dot = document.getElementById('ws-status-dot');
        const text = document.getElementById('ws-status-text');
        if (!dot || !text) return;

        if (status === 'connected') {
            dot.className = 'status-dot online';
            text.textContent = 'Connected (WebSocket)';
        } else if (status === 'connecting') {
            dot.className = 'status-dot connecting';
            text.textContent = 'Connecting...';
        } else {
            dot.className = 'status-dot offline';
            text.textContent = 'Disconnected (Reconnecting...)';
        }
    },

    bindAuthEvents() {
        // Tab switching
        const tabLogin = document.getElementById('tab-login');
        const tabRegister = document.getElementById('tab-register');
        const formLogin = document.getElementById('form-login');
        const formRegister = document.getElementById('form-register');
        const authError = document.getElementById('auth-error-msg');

        tabLogin.onclick = () => {
            tabLogin.classList.add('active');
            tabRegister.classList.remove('active');
            formLogin.style.display = 'block';
            formRegister.style.display = 'none';
            authError.textContent = '';
        };

        tabRegister.onclick = () => {
            tabRegister.classList.add('active');
            tabLogin.classList.remove('active');
            formRegister.style.display = 'block';
            formLogin.style.display = 'none';
            authError.textContent = '';
        };

        // Login submit
        formLogin.onsubmit = async (e) => {
            e.preventDefault();
            authError.textContent = '';
            const uname = document.getElementById('login-username').value;
            const pass = document.getElementById('login-password').value;
            const btn = formLogin.querySelector('button[type="submit"]');

            btn.disabled = true;
            btn.textContent = 'Authenticating...';

            try {
                const res = await window.Auth.login(uname, pass);
                await this.showChatView(res.username);
            } catch (err) {
                authError.textContent = err.message;
            } finally {
                btn.disabled = false;
                btn.textContent = 'Sign In';
            }
        };

        // Register submit
        formRegister.onsubmit = async (e) => {
            e.preventDefault();
            authError.textContent = '';
            const uname = document.getElementById('reg-username').value;
            const pass = document.getElementById('reg-password').value;
            const passConfirm = document.getElementById('reg-password-confirm').value;
            const btn = formRegister.querySelector('button[type="submit"]');

            if (pass !== passConfirm) {
                authError.textContent = 'Passwords do not match';
                return;
            }

            if (pass.length < 8) {
                authError.textContent = 'Password must be at least 8 characters long';
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Generating Cryptographic Keys...';

            try {
                const res = await window.Auth.register(uname, pass);
                await this.showChatView(res.username);
            } catch (err) {
                authError.textContent = err.message;
            } finally {
                btn.disabled = false;
                btn.textContent = 'Create Account & Generate Keys';
            }
        };

        // Logout
        document.getElementById('logout-btn').onclick = () => {
            window.Auth.logout();
        };
    },

    bindChatEvents() {
        // Message submission
        const form = document.getElementById('chat-form');
        const input = document.getElementById('message-input');

        form.onsubmit = (e) => {
            e.preventDefault();
            const text = input.value;
            if (text.trim()) {
                const error = document.getElementById('chat-error-msg');
                if (error) error.textContent = '';
                window.Chat.sendMessage(text).then(() => {
                    input.value = '';
                }).catch((err) => {
                    const error = document.getElementById('chat-error-msg');
                    if (error) error.textContent = err.message;
                });
            }
        };

        // Contact Search
        const searchInput = document.getElementById('contact-search');
        if (searchInput) {
            searchInput.oninput = (e) => {
                window.Chat.renderContactsList(e.target.value);
            };
        }

        // Toggle Security Panel
        const toggleSecBtn = document.getElementById('toggle-security-btn');
        const secPanel = document.getElementById('security-panel');
        const closeSecBtn = document.getElementById('close-security-btn');

        if (toggleSecBtn && secPanel) {
            toggleSecBtn.onclick = () => {
                secPanel.classList.toggle('open');
                window.Chat.updateSecurityPanel();
            };
        }

        if (closeSecBtn && secPanel) {
            closeSecBtn.onclick = () => {
                secPanel.classList.remove('open');
            };
        }

        // Toggle Workflow Visualization Panel
        const headerWfBtn = document.getElementById('header-workflow-btn');
        const toggleWfBtn = document.getElementById('workflow-toggle-btn');
        const wfPanel = document.getElementById('workflow-panel');
        const closeWfBtn = document.getElementById('close-workflow-btn');

        if (headerWfBtn) {
            headerWfBtn.onclick = () => {
                window.Chat.toggleWorkflowPanel();
            };
        }

        if (toggleWfBtn) {
            toggleWfBtn.onclick = () => {
                window.Chat.toggleWorkflowPanel();
            };
        }

        if (closeWfBtn && wfPanel) {
            closeWfBtn.onclick = () => {
                wfPanel.classList.remove('open');
            };
        }

        // Verify Safety Number Checkbox
        const verifyCheck = document.getElementById('verify-identity-checkbox');
        if (verifyCheck) {
            verifyCheck.onchange = (e) => {
                window.Chat.toggleVerifySafetyNumber(e.target.checked);
            };
        }

        // Tamper Attack Demo Controls
        const tamperBtn = document.getElementById('tamper-toggle-btn');
        if (tamperBtn) {
            tamperBtn.onclick = () => {
                window.Chat.toggleTamperSimulation();
            };
        }

        const cancelTamperBtn = document.getElementById('btn-cancel-tamper');
        if (cancelTamperBtn) {
            cancelTamperBtn.onclick = () => {
                window.Chat.toggleTamperSimulation();
            };
        }

        const tamperSelect = document.getElementById('tamper-type-select');
        if (tamperSelect) {
            tamperSelect.onchange = (e) => {
                window.Chat.setTamperMode(e.target.value);
            };
        }

        // Mobile Back Button
        const mobileBackBtn = document.getElementById('mobile-back-btn');
        if (mobileBackBtn) {
            mobileBackBtn.onclick = () => {
                document.getElementById('chat-view').classList.remove('mobile-chat-active');
            };
        }
    }
};

window.App = App;

// Bootstrap on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    window.App.init();
});
