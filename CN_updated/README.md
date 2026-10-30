# End-to-End Encrypted Chat Application (CypherChat)

**Project Title:** 14. End-to-End Encrypted Chat Application: Develop a real-time chat application with end-to-end encryption, forward secrecy, and message authentication to safeguard user privacy.

CypherChat is a real-time, browser-based end-to-end encrypted chat application designed for confidential communication. It combines a FastAPI Python backend, SQLite store-and-forward relay, WebSocket duplex transport, and client-side browser Web Crypto API primitives (ECDH NIST P-256, HKDF-SHA-256, and AES-256-GCM). The server handles account management, presence, and opaque envelope routing; it never receives, stores, or inspects plaintext messages or private keys.

---

## Required Modules & Implementation Coverage

| # | Required Module | Implementation Files | Demonstrated Capabilities |
|---|---|---|---|
| **1** | **User Authentication Module** | `backend/app/auth.py`<br>`backend/app/security.py`<br>`frontend/js/auth.js` | • User registration and secure login.<br>• Argon2id password hashing (RFC 9106) with rate-limiting and temporary lockout.<br>• Authenticated connections using cryptographically signed HS256 JWT access tokens.<br>• WebSocket authentication via `bearer.<JWT>` subprotocol (no token leakage in URL logs). |
| **2** | **End-to-End Encryption Module** | `frontend/js/crypto.js`<br>`frontend/js/chat.js`<br>`backend/app/models.py` | • Messages are encrypted in sender browser prior to network transmission.<br>• Decrypted in recipient browser after reception.<br>• **Actual Values Display:** Plaintext, Ciphertext (Base64), Nonce / IV (12-byte Hex & Base64), 128-bit Auth Tag, and Encryption/Decryption status are inspectable per message and in real time. |
| **3** | **Forward Secrecy Module** | `frontend/js/crypto.js`<br>`frontend/js/chat.js` | • Custom Double Ratchet implementation combining symmetric KDF chains and asymmetric DH steps.<br>• Ephemeral Message Key ($MK$) derived via one-way HKDF-SHA-256 and **immediately erased from memory** after single use.<br>• Conversational turns perform ECDH P-256 ephemeral key exchanges, advancing master root keys.<br>• Past message keys cannot be reversed due to pre-image resistance of SHA-256. |
| **4** | **Message Authentication Module** | `frontend/js/crypto.js`<br>`frontend/js/chat.js` | • AEAD AES-256-GCM computes and verifies a 128-bit authentication tag over ciphertext and nonce.<br>• Detects any modified ciphertext bits, altered nonces, or replayed counters.<br>• Automatically rejects tampered messages and prevents plaintext disclosure.<br>• Sender connection identity enforced on backend WebSocket layer. |
| **5** | **Real-Time Chat Module** | `backend/app/websocket_router.py`<br>`backend/app/websocket_manager.py`<br>`backend/app/message_relay.py` | • Full-duplex WebSocket communication between authenticated users.<br>• Live message delivery state: `⏱ Sending`, `✓ Sent / Queued`, `✓✓ Delivered in real-time`.<br>• Backend relays opaque `EncryptedMessageEnvelope` without possessing plaintext or private keys.<br>• Store-and-forward SQLite queue delivers pending envelopes to offline recipients upon reconnection. |
| **6** | **Encryption & Decryption Visualization Module** | `frontend/index.html`<br>`frontend/js/chat.js`<br>`frontend/css/styles.css` | • **Live 7-Stage Cryptographic Pipeline** rendered in real time:<br>  1. *Original Plaintext* (sender input string)<br>  2. *Sender-Side Encryption* (HKDF KDF step & 12-byte CSPRNG IV)<br>  3. *Generated Ciphertext & Metadata* (Ciphertext, IV Hex, Tag Hex, Msg Counter)<br>  4. *Encrypted WebSocket Payload* (Raw wire JSON with zero plaintext)<br>  5. *Recipient-Side Authentication Verification* (AES-GCM tag verification & sequence check)<br>  6. *Recipient-Side Decryption* (HKDF Message Key derivation & `subtle.decrypt`)<br>  7. *Recovered Plaintext* (Matching original string, or Rejected banner if tampered)<br>• Displays actual generated cryptographic values, not simulated text. |
| **7** | **Tamper Detection Module** | `frontend/js/chat.js`<br>`frontend/js/crypto.js`<br>`frontend/index.html` | • Prominent **⚠️ Simulate Tamper Attack** toggle button with attack mode selector (Ciphertext byte flip, Auth Tag corruption, or Nonce corruption).<br>• Tampered envelope passes through the real WebSocket relay to the recipient.<br>• Recipient Web Crypto API authenticated decryption fails with tag mismatch.<br>• Displays red security integrity alert card and blocks plaintext recovery.<br>• Session ratchet remains synchronized so subsequent legitimate messages succeed. |

---

## Technology Stack

- **Backend:** Python 3.10+, FastAPI, Pydantic 2, Uvicorn, `aiosqlite`, SQLite, `cryptography`, `argon2-cffi`, `python-jose`.
- **Frontend:** HTML5, CSS3, ES6 JavaScript, Browser Web Crypto API (`window.crypto.subtle`), WebSockets.
- **Testing:** pytest, pytest-asyncio, httpx (Python); Node.js built-in test runner (`node --test`) with Web Crypto API.

---

## Windows PowerShell Execution Guide

Run the following commands in Windows PowerShell:

### 1. Project Location

```powershell
Set-Location "C:\Users\pjasw\OneDrive\Desktop\End_to_End_Encrypted_Chat_Application_Updated\CN_updated"
```

### 2. Activate Virtual Environment & Install Dependencies

```powershell
# Set execution policy for current session and activate virtualenv:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1

# Upgrade pip and install requirements (if setting up on a fresh machine):
python -m pip install --upgrade pip
python -m pip install -r backend\requirements.txt
```

### 3. Start the Server

```powershell
# Set random session secret and run Uvicorn on localhost port 8000:
$env:JWT_SECRET_KEY = [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

The application is now live at: <http://127.0.0.1:8000/>.

---

## Automated Test Verification

To run all automated test suites, open a second PowerShell terminal in `CN_updated`:

```powershell
Set-Location "C:\Users\pjasw\OneDrive\Desktop\End_to_End_Encrypted_Chat_Application_Updated\CN_updated"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1

# 1. Run Backend Python Test Suite (16 tests covering API, Auth, WebSocket relay, and Crypto Reference):
.\venv\Scripts\python.exe -m pytest -v

# 2. Run Frontend Web Crypto Test Suite (6 tests covering Ratchet, Tamper detection, Nonce/Tag extraction, E2E Lifecycle):
node --test frontend\tests\crypto.test.js frontend\tests\e2e_crypto_integration.test.js
```

**Test Results:**
- **Python Pytest Suite:** 16 passed (100% pass rate).
- **Node Web Crypto Suite:** 6 passed (100% pass rate).
- **Total:** 22 automated tests validating authentication, encryption, forward secrecy, delivery, and tamper rejection.

---

## Live Demonstration Procedure

Demonstrate every module step-by-step between two users:

1. **User Accounts:**
   - Open <http://127.0.0.1:8000/> in a standard browser window (User 1: `alice`, password: `password123`).
   - Open <http://127.0.0.1:8000/> in an InPrivate / Incognito window (User 2: `bob`, password: `password123`).
   - Both browsers generate client-side ECDH P-256 identity and prekeys on registration.

2. **Real-Time Encrypted Message Exchange:**
   - In Alice's window, select `bob` from the contact list.
   - Send: `"Confidential Project Update"`.
   - Bob receives the message instantly over WebSockets (`✓✓` double checkmark in Alice's view).
   - In Bob's chat, the plaintext is revealed only after client-side AES-256-GCM authenticated decryption.

3. **Inspect Real Cryptographic Parameters:**
   - Click **🔍 Inspect Crypto (AES-GCM)** on the message bubble to display:
     - Plaintext: `"Confidential Project Update"`
     - Ciphertext (Base64)
     - Nonce / IV: 12 bytes in Hex format
     - Auth Tag: 16 bytes (128 bits) in Hex format
     - Ratchet Msg Counter: `#0`

4. **Interactive 7-Stage Workflow Visualization:**
   - Click the **🔬 Workflow Visualizer** button in the header bar.
   - Observe the real-time visual stages update synchronously:
     - **Stage 1 (Plaintext):** User input string.
     - **Stage 2 (Encryption):** HKDF-SHA-256 key derivation & 12-byte CSPRNG IV generation.
     - **Stage 3 (Metadata):** Generated Ciphertext, Hex Nonce, Hex Auth Tag, DH point.
     - **Stage 4 (Payload):** Network JSON envelope demonstrating zero plaintext sent to server.
     - **Stage 5 (Verification):** AES-GCM Tag check `PASSED ✅` and sequence counter check.
     - **Stage 6 (Decryption):** Web Crypto API `subtle.decrypt` invocation and message key erasure.
     - **Stage 7 (Recovered):** Final recovered plaintext matching Stage 1.

5. **Forward Secrecy & Ratchet Progression:**
   - Send a sequence of messages from Alice to observe symmetric KDF chain evolution ($MK_i$ derived and purged).
   - Reply from Bob to trigger the asymmetric DH Ratchet step (fresh ephemeral ECDH P-256 keypair).
   - Open **🛡️ Security Details** to observe root key evolution, message counters, and identity safety number.

6. **Tamper Attack Demonstration:**
   - In Alice's window, click **⚠️ Simulate Tamper Attack**.
   - Select attack target (e.g., *Corrupt Ciphertext Bits*).
   - Send a message. Alice transmits the modified ciphertext over the real WebSocket relay.
   - Bob receives the envelope; Web Crypto API runs `subtle.decrypt`, detects the authentication tag mismatch, and rejects the message.
   - Bob sees a prominent red alert card: **SECURITY INTEGRITY ALERT: TAMPERING DETECTED!**
   - The Workflow Visualizer updates to show Stage 5 **FAILED ❌** and Stages 6 & 7 **ABORTED 🚫**.
   - Send a subsequent valid message: it decrypts cleanly, proving that session state was not corrupted.

7. **Offline Delivery Demonstration:**
   - Close Bob's incognito window. Alice sees Bob's status switch to Offline.
   - Alice sends: `"Offline queued note"`. Alice sees status `✓` (queued offline in SQLite).
   - Re-open Bob's window and sign in: Bob immediately receives and decrypts the queued message, sending an acknowledgement that removes it from the server queue.

---

## Security Boundary & Educational Disclosures

This application is an educational prototype demonstrating E2EE, authenticated decryption, and ratcheted forward secrecy for academic coursework:
- **Client-Side Storage:** Private keys, root keys, and session ratchet states are stored in browser `localStorage`. In production, secure key hardware storage (e.g. WebAuthn or platform TPM keystores) should be utilized.
- **Protocol Boundary:** The ratchet implementation illustrates Double Ratchet concepts using established Web Crypto primitives (P-256, HKDF-SHA-256, AES-256-GCM). It does not buffer out-of-order skipped messages and is not an audited Signal Protocol implementation.
- **Transport Security:** For local demonstration, unencrypted `ws://` on loopback is used. Production deployments require TLS/WSS (`https://` and `wss://`).
