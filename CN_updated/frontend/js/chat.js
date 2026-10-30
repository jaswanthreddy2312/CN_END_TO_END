/**
 * Chat Controller & Real-Time E2EE Messaging Module
 * Integrates:
 * - End-to-End Encryption (AES-256-GCM, ECDH P-256, HKDF-SHA-256)
 * - Custom Double Ratchet Forward Secrecy & Ephemeral Key Erasure
 * - Authenticated Decryption & Tamper Detection
 * - Real-Time 7-Stage Cryptographic Workflow Visualization
 */

const Chat = {
    activeContact: null,
    contacts: new Map(), // username -> contact object
    messages: new Map(), // username -> array of message objects
    lastWirePayload: null,
    isTamperDemoActive: false,
    tamperMode: 'ciphertext', // 'ciphertext', 'tag', 'iv'
    activeWorkflowData: null,
    expandedCryptoMsgIds: new Set(),

    async init() {
        this.currentUser = window.Auth.getUsername();
        this.loadLocalMessages();
        await this.loadContacts();
    },

    loadLocalMessages() {
        const key = `e2ee_history_${this.currentUser.toLowerCase()}`;
        const stored = localStorage.getItem(key);
        if (stored) {
            try {
                const parsed = JSON.parse(stored);
                for (const [k, v] of Object.entries(parsed)) {
                    this.messages.set(k.toLowerCase(), v);
                }
            } catch (e) {
                console.error("Failed to load local history:", e);
            }
        }
    },

    saveLocalMessages() {
        const key = `e2ee_history_${this.currentUser.toLowerCase()}`;
        const obj = {};
        for (const [k, v] of this.messages.entries()) {
            obj[k] = v;
        }
        localStorage.setItem(key, JSON.stringify(obj));
    },

    async loadContacts() {
        const token = window.Auth.getToken();
        try {
            const res = await fetch('/api/users', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (!res.ok) throw new Error('Failed to load contacts');
            const userList = await res.json();
            
            this.contacts.clear();
            userList.forEach(u => {
                if (u.username.toLowerCase() !== this.currentUser.toLowerCase()) {
                    this.contacts.set(u.username.toLowerCase(), u);
                }
            });

            this.renderContactsList();
        } catch (err) {
            console.error('Error loading contacts:', err);
        }
    },

    async updateUserStatus(username, status) {
        const key = username.toLowerCase();
        let contact = this.contacts.get(key);
        if (!contact) {
            await this.loadContacts();
            contact = this.contacts.get(key);
            if (!contact) return;
        }
        contact.is_online = (status === 'online');
        this.renderContactsList();
        if (this.activeContact && this.activeContact.username.toLowerCase() === key) {
            this.updateChatHeader();
        }
    },

    syncOnlineUsers(onlineUsers) {
        const onlineSet = new Set(onlineUsers.map(u => u.toLowerCase()));
        for (const [uname, contact] of this.contacts.entries()) {
            contact.is_online = onlineSet.has(uname);
        }
        this.renderContactsList();
        if (this.activeContact) {
            this.updateChatHeader();
        }
    },

    renderContactsList(filterText = '') {
        const container = document.getElementById('contacts-list');
        if (!container) return;
        container.innerHTML = '';

        const filter = filterText.toLowerCase();
        let renderedCount = 0;

        for (const [uname, contact] of this.contacts.entries()) {
            if (filter && !contact.username.toLowerCase().includes(filter)) {
                continue;
            }

            renderedCount++;
            const li = document.createElement('div');
            const isActive = this.activeContact && this.activeContact.username.toLowerCase() === uname;
            li.className = `contact-item ${isActive ? 'active' : ''}`;
            
            // Get last message snippet
            const history = this.messages.get(uname) || [];
            const lastMsg = history.length > 0 ? history[history.length - 1] : null;
            let lastText = 'No messages yet';
            if (lastMsg) {
                lastText = lastMsg.isTampered ? '⚠️ Tampered message rejected' : (lastMsg.sender === this.currentUser ? `You: ${lastMsg.text}` : lastMsg.text);
            }

            li.innerHTML = `
                <div class="avatar-container">
                    <div class="avatar">${contact.username.charAt(0).toUpperCase()}</div>
                    <span class="status-dot ${contact.is_online ? 'online' : 'offline'}"></span>
                </div>
                <div class="contact-info">
                    <div class="contact-header">
                        <span class="contact-name">${contact.username}</span>
                        <span class="contact-time">${lastMsg ? this.formatTime(lastMsg.timestamp) : ''}</span>
                    </div>
                    <div class="contact-snippet">${this.escapeHtml(lastText)}</div>
                </div>
            `;

            li.onclick = () => this.selectContact(contact);
            container.appendChild(li);
        }

        if (renderedCount === 0) {
            container.innerHTML = `<div class="empty-state">No contacts found</div>`;
        }
    },

    async selectContact(contact) {
        this.activeContact = contact;
        this.renderContactsList();
        this.updateChatHeader();
        this.renderMessages();
        await this.updateSecurityPanel();

        // If there's message history, show the latest in visualizer
        const history = this.messages.get(contact.username.toLowerCase()) || [];
        if (history.length > 0) {
            const latest = history[history.length - 1];
            if (latest.crypto) {
                this.renderWorkflowVisualization(latest.crypto, latest.sender, contact.username);
            }
        }

        const input = document.getElementById('message-input');
        if (input) input.focus();

        // On mobile, show chat area
        document.getElementById('chat-view').classList.add('mobile-chat-active');
    },

    updateChatHeader() {
        if (!this.activeContact) return;
        document.getElementById('chat-partner-name').textContent = this.activeContact.username;
        const statusEl = document.getElementById('chat-partner-status');
        if (this.activeContact.is_online) {
            statusEl.className = 'status-badge online';
            statusEl.innerHTML = '<span class="status-dot online"></span> Online (WebSocket Active)';
        } else {
            statusEl.className = 'status-badge offline';
            statusEl.innerHTML = '<span class="status-dot offline"></span> Offline (Store-and-Forward)';
        }

        // Check if session verified
        const sessionKey = window.e2eeCrypto.getSessionKey(this.currentUser, this.activeContact.username);
        const isVerified = localStorage.getItem(`${sessionKey}_verified`) === 'true';
        const verifyBadge = document.getElementById('header-verify-badge');
        if (verifyBadge) {
            if (isVerified) {
                verifyBadge.className = 'security-badge verified';
                verifyBadge.innerHTML = '🛡️ Verified Identity';
            } else {
                verifyBadge.className = 'security-badge unverified';
                verifyBadge.innerHTML = '🔒 E2EE Active';
            }
        }
    },

    renderMessages() {
        const container = document.getElementById('messages-container');
        if (!container || !this.activeContact) return;
        container.innerHTML = '';

        const history = this.messages.get(this.activeContact.username.toLowerCase()) || [];

        if (history.length === 0) {
            container.innerHTML = `
                <div class="chat-empty-notice">
                    <div class="lock-icon-large">🔒</div>
                    <h3>End-to-End Encrypted Session</h3>
                    <p>Messages to <strong>${this.activeContact.username}</strong> are encrypted client-side using ECDH NIST P-256, HKDF-SHA-256, and AES-256-GCM. Forward secrecy is enforced via ratcheting ephemeral message keys.</p>
                </div>
            `;
            return;
        }

        history.forEach(msg => {
            const isMe = msg.sender.toLowerCase() === this.currentUser.toLowerCase();
            const bubble = document.createElement('div');
            const isExpanded = this.expandedCryptoMsgIds.has(msg.id);

            if (msg.isTampered) {
                bubble.className = 'message-row tampered';
                bubble.innerHTML = `
                    <div class="tamper-alert-card">
                        <div class="tamper-alert-header">
                            <span class="warning-icon">⚠️</span>
                            <strong>SECURITY INTEGRITY ALERT: TAMPERING DETECTED!</strong>
                        </div>
                        <p>The cryptographic authentication tag for this message failed verification. Ciphertext bits were modified in transit or an unauthorized replay occurred. Decryption was blocked.</p>
                        <div class="tamper-meta">
                            Sender: ${this.escapeHtml(msg.sender)} • ${this.formatTime(msg.timestamp)} • Status: Rejected
                        </div>
                        <button class="btn-inspect-crypto" onclick="window.Chat.toggleMessageCryptoDetails('${msg.id}')">
                            🔍 ${isExpanded ? 'Hide Cryptographic Breakdown' : 'Inspect Authentication Failure & Tag'}
                        </button>
                        ${isExpanded ? this.renderInlineCryptoCard(msg) : ''}
                    </div>
                `;
            } else {
                bubble.className = `message-row ${isMe ? 'outgoing' : 'incoming'}`;
                
                let statusIcon = '';
                if (isMe) {
                    if (msg.status === 'delivered') {
                        statusIcon = '<span class="msg-status delivered" title="Delivered in real-time">✓✓</span>';
                    } else if (msg.status === 'sent') {
                        statusIcon = '<span class="msg-status sent" title="Sent (queued / relayed)">✓</span>';
                    } else {
                        statusIcon = '<span class="msg-status sending" title="Encrypting & transmitting">⏱</span>';
                    }
                }

                bubble.innerHTML = `
                    <div class="message-bubble ${isMe ? 'bubble-me' : 'bubble-them'}">
                        <div class="message-text">${this.escapeHtml(msg.text)}</div>
                        <div class="message-footer">
                            <span class="message-time">${this.formatTime(msg.timestamp)}</span>
                            ${statusIcon}
                            <span class="e2ee-lock-icon" title="End-to-end encrypted with AES-256-GCM">🔒</span>
                        </div>
                        <button class="btn-inspect-crypto" onclick="window.Chat.toggleMessageCryptoDetails('${msg.id}')">
                            🔍 ${isExpanded ? 'Hide Crypto Values' : 'Inspect Ciphertext, Nonce & Tag'}
                        </button>
                        ${isExpanded ? this.renderInlineCryptoCard(msg) : ''}
                    </div>
                `;
            }

            container.appendChild(bubble);
        });

        // Scroll to bottom
        container.scrollTop = container.scrollHeight;
    },

    renderInlineCryptoCard(msg) {
        const c = msg.crypto || {};
        const isTampered = !!msg.isTampered;
        return `
            <div class="message-crypto-details">
                <div class="crypto-detail-row">
                    <span class="detail-key">Actual Plaintext:</span>
                    <span class="detail-val">${isTampered ? '[REJECTED: Plaintext Withheld]' : this.escapeHtml(msg.text)}</span>
                </div>
                <div class="crypto-detail-row">
                    <span class="detail-key">Ciphertext (Base64):</span>
                    <span class="detail-val">${this.escapeHtml(c.ciphertextBase64 || '—')}</span>
                </div>
                <div class="crypto-detail-row">
                    <span class="detail-key">Nonce / IV (12-byte Hex):</span>
                    <span class="detail-val">${this.escapeHtml(c.nonceHex || '—')}</span>
                </div>
                <div class="crypto-detail-row">
                    <span class="detail-key">AES-GCM Auth Tag (16-byte Hex):</span>
                    <span class="detail-val tag-highlight">${this.escapeHtml(c.authTagHex || '—')}</span>
                </div>
                <div class="crypto-detail-row">
                    <span class="detail-key">Ratchet Msg Counter:</span>
                    <span class="detail-val">#${c.msgCounter ?? '0'} (Forward Secrecy Step)</span>
                </div>
                <div class="crypto-detail-row">
                    <span class="detail-key">Authentication Status:</span>
                    <span class="detail-val ${isTampered ? 'tampered-fail' : ''}">
                        ${isTampered ? '❌ FAILED (Tag Mismatch / Tamper Detected)' : '✅ PASSED (AES-256-GCM Tag Verified)'}
                    </span>
                </div>
                <button class="btn-open-wf-msg" onclick="window.Chat.showWorkflowForMessage('${msg.id}')">
                    Open in 7-Stage Workflow Visualizer →
                </button>
            </div>
        `;
    },

    toggleMessageCryptoDetails(messageId) {
        if (this.expandedCryptoMsgIds.has(messageId)) {
            this.expandedCryptoMsgIds.delete(messageId);
        } else {
            this.expandedCryptoMsgIds.add(messageId);
        }
        this.renderMessages();
    },

    showWorkflowForMessage(messageId) {
        if (!this.activeContact) return;
        const history = this.messages.get(this.activeContact.username.toLowerCase()) || [];
        const msg = history.find(m => m.id === messageId);
        if (msg && msg.crypto) {
            this.renderWorkflowVisualization(msg.crypto, msg.sender, msg.recipient || this.activeContact.username);
            const panel = document.getElementById('workflow-panel');
            if (panel) panel.classList.add('open');
        }
    },

    async sendMessage(text) {
        if (!this.activeContact || !text || !text.trim()) return;
        const recipient = this.activeContact.username;
        const plainText = text.trim();

        // 1. Ensure E2EE session exists (Initial X3DH handshake if needed)
        let session = window.e2eeCrypto.loadSession(this.currentUser, recipient);
        const previousSession = session ? JSON.parse(JSON.stringify(session)) : null;
        let isInitial = false;
        let handshakeData = null;

        if (!session) {
            const peerIkJwk = JSON.parse(this.activeContact.identity_pubkey);
            const peerSpkJwk = JSON.parse(this.activeContact.prekey_pubkey);
            const signedPrekeyJwk = this.activeContact.signed_prekey_pubkey ? JSON.parse(this.activeContact.signed_prekey_pubkey) : null;
            const signedPrekeySignature = this.activeContact.signed_prekey_signature || null;

            const initResult = await window.e2eeCrypto.initializeOutboundSession(
                this.currentUser,
                recipient,
                peerIkJwk,
                peerSpkJwk,
                signedPrekeyJwk,
                signedPrekeySignature
            );
            session = initResult.session;
            handshakeData = initResult.handshake;
            isInitial = true;
        }

        // 2. Encrypt using custom Double Ratchet (ECDH / HKDF / AES-256-GCM)
        const tamperParam = this.isTamperDemoActive ? (this.tamperMode || 'ciphertext') : false;
        const envelope = await window.e2eeCrypto.encrypt(
            this.currentUser,
            recipient,
            plainText,
            tamperParam
        );

        if (isInitial && handshakeData) {
            envelope.is_initial = true;
            envelope.ephemeral_pubkey = handshakeData.ephemeral_pubkey;
        }

        if (this.isTamperDemoActive && isInitial) {
            window.e2eeCrypto.removeSession(this.currentUser, recipient);
        }

        // The demo-corrupted packet must not consume a message key on the sender.
        const restoreSession = () => {
            if (previousSession) {
                window.e2eeCrypto.saveSession(this.currentUser, recipient, previousSession);
            } else {
                window.e2eeCrypto.removeSession(this.currentUser, recipient);
            }
        };

        let sent;
        try {
            sent = window.App.sendWebSocketMessage({
                type: 'send_encrypted_message',
                payload: envelope
            });
        } catch (err) {
            restoreSession();
            throw err;
        }
        if (!sent) {
            restoreSession();
            throw new Error('Not connected to the chat server. Reconnect before sending.');
        }

        const wasTamperActive = this.isTamperDemoActive;
        const usedTamperMode = this.tamperMode;

        // Reset tamper demo toggle after one use
        if (this.isTamperDemoActive) {
            this.isTamperDemoActive = false;
            this.updateTamperBannerState();
        }

        // 3. Build rich cryptographic diagnostics
        const msgId = envelope.message_id;
        const nonceHex = window.e2eeCrypto.extractNonceHex(envelope.iv);
        const authTagHex = window.e2eeCrypto.extractAuthTagHex(envelope.ciphertext);
        const ctHex = window.e2eeCrypto.extractCiphertextHex(envelope.ciphertext);

        const cryptoData = {
            plaintext: plainText,
            ciphertextBase64: envelope.ciphertext,
            ciphertextHex: ctHex,
            nonceBase64: envelope.iv,
            nonceHex: nonceHex,
            authTagHex: authTagHex,
            msgCounter: envelope.msg_counter,
            prevChainLen: envelope.prev_chain_len,
            dhRatchetPubkey: envelope.dh_ratchet_pubkey,
            wirePayload: envelope,
            isSender: true,
            isTampered: wasTamperActive,
            tamperMode: wasTamperActive ? usedTamperMode : null,
            status: wasTamperActive ? 'Simulated Tamper Envelope Sent' : 'AES-256-GCM Encrypted (Sender)'
        };

        // 4. Store local message bubble
        const history = this.messages.get(recipient.toLowerCase()) || [];
        const msgObj = {
            id: msgId,
            sender: this.currentUser,
            recipient: recipient,
            text: plainText,
            timestamp: envelope.timestamp,
            status: 'sending',
            isTampered: wasTamperActive,
            crypto: cryptoData
        };
        history.push(msgObj);
        this.messages.set(recipient.toLowerCase(), history);
        this.saveLocalMessages();
        this.renderMessages();
        this.renderContactsList();

        // 5. Update Real-Time Workflow Visualization & Inspector
        this.lastWirePayload = envelope;
        this.renderWorkflowVisualization(cryptoData, this.currentUser, recipient);
        this.updateWireInspector();
        await this.updateSecurityPanel();
    },

    async handleIncomingMessage(envelope) {
        const sender = envelope.sender;
        const senderKey = sender.toLowerCase();

        // 1. Ensure sender is in contacts list
        let senderContact = this.contacts.get(senderKey);
        if (!senderContact) {
            await this.loadContacts();
            senderContact = this.contacts.get(senderKey);
        }

        const senderIkJwk = senderContact ? JSON.parse(senderContact.identity_pubkey) : null;

        // 2. Save wire payload
        this.lastWirePayload = envelope;
        this.updateWireInspector();

        const history = this.messages.get(senderKey) || [];
        const existingIndex = history.findIndex((message) => message.id === envelope.message_id);
        if (existingIndex >= 0 && !history[existingIndex].isTampered) {
            window.App.sendWebSocketMessage({
                type: 'message_received',
                message_id: envelope.message_id
            });
            return;
        }

        // 3. Attempt client-side authenticated decryption via Web Crypto API
        let decryptedText = null;
        let isTampered = false;
        let tamperError = null;

        try {
            decryptedText = await window.e2eeCrypto.decrypt(
                this.currentUser,
                sender,
                envelope,
                senderIkJwk
            );
        } catch (err) {
            console.warn("Decryption/Integrity failure:", err);
            isTampered = true;
            tamperError = err.message;
        }

        // 4. Capture diagnostic values
        const nonceHex = window.e2eeCrypto.extractNonceHex(envelope.iv);
        const authTagHex = window.e2eeCrypto.extractAuthTagHex(envelope.ciphertext);
        const ctHex = window.e2eeCrypto.extractCiphertextHex(envelope.ciphertext);

        const cryptoData = {
            plaintext: decryptedText,
            ciphertextBase64: envelope.ciphertext,
            ciphertextHex: ctHex,
            nonceBase64: envelope.iv,
            nonceHex: nonceHex,
            authTagHex: authTagHex,
            msgCounter: envelope.msg_counter,
            prevChainLen: envelope.prev_chain_len,
            dhRatchetPubkey: envelope.dh_ratchet_pubkey,
            wirePayload: envelope,
            isSender: false,
            isTampered: isTampered,
            tamperError: tamperError,
            status: isTampered ? 'Authentication Tag Verification Failed (Rejected)' : 'Decrypted & Authenticated (Recipient)'
        };

        const receivedMessage = {
            id: envelope.message_id,
            sender: sender,
            recipient: this.currentUser,
            text: isTampered ? '[Tampered Message Rejected - Authentication Failed]' : decryptedText,
            timestamp: envelope.timestamp,
            status: isTampered ? 'tampered' : 'received',
            isTampered: isTampered,
            crypto: cryptoData
        };

        if (existingIndex >= 0) {
            history[existingIndex] = receivedMessage;
        } else {
            history.push(receivedMessage);
        }
        this.messages.set(senderKey, history);
        this.saveLocalMessages();

        window.App.sendWebSocketMessage({
            type: 'message_received',
            message_id: envelope.message_id
        });

        if (this.activeContact && this.activeContact.username.toLowerCase() === senderKey) {
            this.renderMessages();
            this.renderWorkflowVisualization(cryptoData, sender, this.currentUser);
            await this.updateSecurityPanel();
        }
        this.renderContactsList();
    },

    renderWorkflowVisualization(c, sender = '', recipient = '') {
        this.activeWorkflowData = c;
        const targetEl = document.getElementById('workflow-current-target');
        if (targetEl) {
            targetEl.textContent = `Active: ${sender || '—'} → ${recipient || '—'} (Counter #${c.msgCounter ?? 0})`;
        }

        // Stage 1: Plaintext
        const s1Box = document.getElementById('wf-s1-plaintext');
        const s1Meta = document.getElementById('wf-s1-meta');
        if (s1Box) {
            if (c.isTampered && !c.isSender) {
                s1Box.className = 'stage-data-box tampered-fail';
                s1Box.textContent = '[REJECTED: Plaintext withheld to protect recipient integrity]';
                if (s1Meta) s1Meta.textContent = 'Recipient browser prevented disclosure due to authentication failure.';
            } else {
                s1Box.className = 'stage-data-box';
                s1Box.textContent = c.plaintext || '// No plaintext available';
                if (s1Meta) s1Meta.textContent = `UTF-8 Encoding • ${(c.plaintext || '').length} characters • Exists solely on client`;
            }
        }

        // Stage 2: Sender-Side Encryption
        const s2Nonce = document.getElementById('wf-s2-nonce');
        if (s2Nonce) {
            s2Nonce.textContent = c.nonceHex || '12-byte CSPRNG IV';
        }

        // Stage 3: Generated Ciphertext & Metadata
        const s3Ct = document.getElementById('wf-s3-ciphertext');
        const s3Nonce = document.getElementById('wf-s3-nonce-hex');
        const s3Tag = document.getElementById('wf-s3-tag');
        const s3Counter = document.getElementById('wf-s3-counter');
        const s3Ratchet = document.getElementById('wf-s3-ratchet-state');

        if (s3Ct) s3Ct.textContent = c.ciphertextBase64 || '// None';
        if (s3Nonce) s3Nonce.textContent = c.nonceHex || '// None';
        if (s3Tag) s3Tag.textContent = c.authTagHex || '// None';
        if (s3Counter) s3Counter.textContent = `#${c.msgCounter ?? 0}`;
        if (s3Ratchet) s3Ratchet.textContent = `Chain step n = ${c.msgCounter ?? 0}`;

        // Stage 4: Network Payload
        const s4Payload = document.getElementById('wf-s4-payload');
        if (s4Payload) {
            s4Payload.textContent = c.wirePayload ? JSON.stringify(c.wirePayload, null, 2) : '// No wire payload';
        }

        // Stage 5: Recipient-Side Authentication Verification
        const s5Box = document.getElementById('wf-s5-box');
        const s5Tag = document.getElementById('wf-s5-tag-status');
        const s5Details = document.getElementById('wf-s5-details');
        const s5Badge = document.getElementById('wf-s5-badge');

        if (s5Box && s5Tag) {
            if (c.isTampered) {
                s5Box.className = 'verification-status-box failed';
                s5Tag.innerHTML = '<strong>❌ FAILED: AES-256-GCM Tag Mismatch (Tamper Detected)</strong>';
                if (s5Details) {
                    s5Details.textContent = 'Browser Web Crypto API rejected the authentication tag. Ciphertext or IV was modified in transit. Plaintext release aborted.';
                }
                if (s5Badge) {
                    s5Badge.className = 'stage-badge badge-danger';
                    s5Badge.textContent = 'Attack Detected';
                }
            } else {
                s5Box.className = 'verification-status-box passed';
                s5Tag.innerHTML = '<strong>✅ PASSED: AES-GCM 128-bit Authentication Tag Verified</strong>';
                if (s5Details) {
                    s5Details.textContent = 'Integrity verified: Ciphertext, IV, and ratchet headers match the sender authentication tag. No unauthorized alteration occurred.';
                }
                if (s5Badge) {
                    s5Badge.className = 'stage-badge badge-success';
                    s5Badge.textContent = 'Integrity Valid';
                }
            }
        }

        // Stage 6: Decryption Execution
        const s6Chain = document.getElementById('wf-s6-chain-status');
        const s6Badge = document.getElementById('wf-s6-badge');
        if (s6Chain) {
            if (c.isTampered) {
                s6Chain.textContent = '🚫 Decryption halted by browser crypto engine; key erased.';
                if (s6Badge) {
                    s6Badge.className = 'stage-badge badge-danger';
                    s6Badge.textContent = 'Aborted';
                }
            } else {
                s6Chain.textContent = 'Receiving chain advanced via HKDF-SHA-256; Message Key purged immediately.';
                if (s6Badge) {
                    s6Badge.className = 'stage-badge badge-success';
                    s6Badge.textContent = 'Success';
                }
            }
        }

        // Stage 7: Recovered Plaintext
        const s7Box = document.getElementById('wf-s7-plaintext');
        const s7Meta = document.getElementById('wf-s7-meta');
        const s7Badge = document.getElementById('wf-s7-badge');
        if (s7Box) {
            if (c.isTampered) {
                s7Box.className = 'stage-data-box tampered-fail';
                s7Box.textContent = '[REJECTED: Plaintext Withheld]';
                if (s7Meta) s7Meta.textContent = 'Zero plaintext disclosed to recipient application.';
                if (s7Badge) {
                    s7Badge.className = 'stage-badge badge-danger';
                    s7Badge.textContent = 'Blocked';
                }
            } else {
                s7Box.className = 'stage-data-box';
                s7Box.textContent = c.plaintext || '// Awaiting decryption';
                if (s7Meta) s7Meta.textContent = 'Decrypted plaintext matches original sender input exactly.';
                if (s7Badge) {
                    s7Badge.className = 'stage-badge badge-success';
                    s7Badge.textContent = 'Recovered';
                }
            }
        }
    },

    toggleWorkflowPanel() {
        const panel = document.getElementById('workflow-panel');
        if (!panel) return;
        panel.classList.toggle('open');
        if (panel.classList.contains('open') && !this.activeWorkflowData && this.activeContact) {
            const history = this.messages.get(this.activeContact.username.toLowerCase()) || [];
            if (history.length > 0) {
                const latest = history[history.length - 1];
                if (latest.crypto) {
                    this.renderWorkflowVisualization(latest.crypto, latest.sender, this.activeContact.username);
                }
            }
        }
    },

    toggleTamperSimulation() {
        this.isTamperDemoActive = !this.isTamperDemoActive;
        this.updateTamperBannerState();
    },

    setTamperMode(mode) {
        this.tamperMode = mode;
        const descEl = document.getElementById('tamper-banner-desc');
        if (descEl) {
            if (mode === 'ciphertext') {
                descEl.textContent = 'Next message will have modified bits injected into ciphertext (Byte 0 flip) before WebSocket transmission.';
            } else if (mode === 'tag') {
                descEl.textContent = 'Next message will have corrupted authentication tag bits injected before WebSocket transmission.';
            } else if (mode === 'iv') {
                descEl.textContent = 'Next message will have a corrupted nonce / IV injected before WebSocket transmission.';
            }
        }
    },

    updateTamperBannerState() {
        const btn = document.getElementById('tamper-toggle-btn');
        const banner = document.getElementById('tamper-banner');
        if (this.isTamperDemoActive) {
            if (btn) btn.classList.add('active');
            if (banner) banner.style.display = 'flex';
            this.setTamperMode(this.tamperMode || 'ciphertext');
        } else {
            if (btn) btn.classList.remove('active');
            if (banner) banner.style.display = 'none';
        }
    },

    handleMessageAck(ack) {
        const recipientKey = ack.recipient.toLowerCase();
        const history = this.messages.get(recipientKey) || [];
        const msg = history.find(m => m.id === ack.message_id);
        if (msg) {
            msg.status = ack.status; // 'delivered' or 'sent'
            this.saveLocalMessages();
            if (this.activeContact && this.activeContact.username.toLowerCase() === recipientKey) {
                this.renderMessages();
            }
        }
    },

    handleServerError(error) {
        if (typeof error.message_id !== 'string') return;
        for (const [username, history] of this.messages.entries()) {
            const message = history.find((item) => item.id === error.message_id);
            if (message) {
                message.status = 'failed';
                this.saveLocalMessages();
                if (this.activeContact && this.activeContact.username.toLowerCase() === username) {
                    this.renderMessages();
                }
                return;
            }
        }
    },

    async updateSecurityPanel() {
        if (!this.activeContact) return;
        const panel = document.getElementById('security-panel');
        if (!panel) return;

        const session = window.e2eeCrypto.loadSession(this.currentUser, this.activeContact.username);
        const myKeys = await window.e2eeCrypto.getUserKeys(this.currentUser);
        const peerIkJwk = JSON.parse(this.activeContact.identity_pubkey);

        const safetyNumber = await window.e2eeCrypto.computeSafetyNumber(myKeys.ik_pub_jwk, peerIkJwk);

        const identityCurrentEl = document.getElementById('identity-current-contact');
        if (identityCurrentEl) identityCurrentEl.textContent = this.activeContact.username;

        const identityFingerprintEl = document.getElementById('identity-fingerprint-display');
        if (identityFingerprintEl) identityFingerprintEl.textContent = safetyNumber;

        const prekeyStatusEl = document.getElementById('identity-key-verification-status');
        const verificationStateEl = document.getElementById('identity-contact-verification-state');
        const identityWarningEl = document.getElementById('identity-key-change-warning');

        let prekeyCheck = { valid: false, reason: 'No signed prekey metadata is available for this contact.' };
        if (this.activeContact.signed_prekey_pubkey && this.activeContact.signed_prekey_signature) {
            const signedPrekeyJwk = JSON.parse(this.activeContact.signed_prekey_pubkey);
            prekeyCheck = await window.e2eeCrypto.verifySignedPrekey(peerIkJwk, signedPrekeyJwk, this.activeContact.signed_prekey_signature);
        }

        if (prekeyStatusEl) prekeyStatusEl.textContent = prekeyCheck.reason;
        if (verificationStateEl) verificationStateEl.textContent = prekeyCheck.valid ? 'Verified' : 'Unverified';

        const fingerprintKey = `e2ee_fp_${this.currentUser.toLowerCase()}_${this.activeContact.username.toLowerCase()}`;
        const priorFingerprint = localStorage.getItem(fingerprintKey);
        if (identityWarningEl) {
            if (priorFingerprint && priorFingerprint !== safetyNumber) {
                identityWarningEl.textContent = 'Identity key change detected — re-verify contact before trusting this session.';
            } else if (priorFingerprint) {
                identityWarningEl.textContent = 'No identity-key change detected.';
            } else {
                identityWarningEl.textContent = 'No prior fingerprint recorded yet.';
            }
        }
        localStorage.setItem(fingerprintKey, safetyNumber);

        const safetyNumEl = document.getElementById('safety-number-display');
        if (safetyNumEl) safetyNumEl.textContent = safetyNumber;

        const sessionKey = window.e2eeCrypto.getSessionKey(this.currentUser, this.activeContact.username);
        const isVerified = localStorage.getItem(`${sessionKey}_verified`) === 'true';
        const verifyToggle = document.getElementById('verify-identity-checkbox');
        if (verifyToggle) verifyToggle.checked = isVerified;

        // Ratchet details
        const ratchetStepEl = document.getElementById('ratchet-step-display');
        const msgCountEl = document.getElementById('ratchet-msg-count-display');
        if (session) {
            if (ratchetStepEl) ratchetStepEl.textContent = `${session.isInitiator ? 'Initiator' : 'Receiver'} (Root Key Ratchet Active)`;
            if (msgCountEl) msgCountEl.textContent = `Sent: ${session.sendCounter} • Recv: ${session.recvCounter}`;
        } else {
            if (ratchetStepEl) ratchetStepEl.textContent = 'Pending First Handshake';
            if (msgCountEl) msgCountEl.textContent = '0 messages';
        }

        this.updateWireInspector();
    },

    toggleVerifySafetyNumber(verified) {
        if (!this.activeContact) return;
        const sessionKey = window.e2eeCrypto.getSessionKey(this.currentUser, this.activeContact.username);
        localStorage.setItem(`${sessionKey}_verified`, verified ? 'true' : 'false');
        this.updateChatHeader();
    },

    updateWireInspector() {
        const codeEl = document.getElementById('wire-payload-code');
        if (!codeEl) return;
        if (this.lastWirePayload) {
            codeEl.textContent = JSON.stringify(this.lastWirePayload, null, 2);
        } else {
            codeEl.textContent = '// No messages transmitted yet in this session.';
        }
    },

    formatTime(ts) {
        const d = new Date(ts);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    },

    escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
};

window.Chat = Chat;
