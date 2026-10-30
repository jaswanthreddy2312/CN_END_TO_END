# Start Here: Windows PowerShell Guide

Run these commands from the `CN_updated` project root. The FastAPI server serves both the authenticated API and the frontend; no separate frontend server is needed.

## 1. Open the project directory in PowerShell

```powershell
Set-Location "C:\Users\pjasw\OneDrive\Desktop\End_to_End_Encrypted_Chat_Application_Updated\CN_updated"
```

## 2. Activate the Python virtual environment

The virtual environment already exists in `venv`. To activate it in your current PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

If setting up on a completely new machine or fresh checkout:
```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend\requirements.txt
```

## 3. Start the FastAPI Application Server

Set a random session secret and start the Uvicorn server:

```powershell
$env:JWT_SECRET_KEY = [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Keep this PowerShell window running. Uvicorn will start and initialize the SQLite database automatically.

## 4. Open the Application in Browsers

Open <http://127.0.0.1:8000/> in two separate browser profiles to demonstrate two users:
- **User 1 (e.g., Alice):** Normal Chrome/Edge window.
- **User 2 (e.g., Bob):** Incognito / InPrivate browser window.

Each browser session generates its own ECDH P-256 identity key and prekey client-side in the browser.

## 5. Demonstration Checklist & Workflow

1. **User Authentication Module:**
   - Register account `alice` (password: `password123`).
   - Register account `bob` in the incognito window (password: `password123`).
   - Both users are signed in and display in each other's contact lists with real-time online status.

2. **End-to-End Encryption & Real-Time Messaging:**
   - In Alice's window, click on `bob`.
   - Type a secret message and click **Send**.
   - Observe real-time delivery over WebSockets (double checkmark `✓✓`).
   - In Bob's window, observe the message automatically decrypted client-side.
   - Click **🔍 Inspect Crypto (AES-GCM)** on the message bubble to view:
     - Actual Plaintext
     - Actual Ciphertext (Base64)
     - Actual Nonce / IV (12-byte Hex)
     - Actual AES-GCM Authentication Tag (16-byte Hex)
     - Ratchet Msg Counter and Encryption/Decryption Status.

3. **Encryption & Decryption Visualization Module (7-Stage Pipeline):**
   - Click the **🔬 Workflow Visualizer** button in the header or on any message bubble.
   - The visualizer displays the complete 7-stage cryptographic execution in real time:
     - **Stage 1:** Original Plaintext
     - **Stage 2:** Sender-Side Encryption (HKDF-SHA-256 KDF & 12-byte CSPRNG Nonce)
     - **Stage 3:** Generated Ciphertext & Metadata (Ciphertext, Nonce Hex, 128-bit Auth Tag, Msg Counter)
     - **Stage 4:** Encrypted WebSocket Payload (Raw JSON wire envelope verifying zero plaintext sent to server)
     - **Stage 5:** Recipient-Side Authentication Verification (AES-GCM tag verification & sequence check)
     - **Stage 6:** Recipient-Side Decryption (HKDF key derivation & Web Crypto `subtle.decrypt`)
     - **Stage 7:** Recovered Plaintext (Decrypted string matching sender plaintext)

4. **Forward Secrecy & Ratchet Key Rotation:**
   - Send sequential messages from Alice to observe symmetric KDF chain evolution ($MK_i$ derived via HKDF and immediately purged from memory).
   - Reply from Bob to Alice to trigger an asymmetric DH Ratchet step (generating a fresh ephemeral ECDH P-256 keypair and rotating the master root key).
   - Open **🛡️ Security Details** to observe the updated root key, sending/receiving counters, and contact Safety Number.

5. **Tamper Detection Module:**
   - In Alice's window, click **⚠️ Simulate Tamper Attack**.
   - An active warning banner appears: select corruption type (corrupt ciphertext byte, auth tag, or IV).
   - Send a message. The modified ciphertext is transmitted over WebSockets.
   - In Bob's window, the Web Crypto API authenticated decryption rejects the modified payload:
     - Displays a prominent red alert card: **SECURITY INTEGRITY ALERT: TAMPERING DETECTED!**
     - Recipient withholding plaintext to protect integrity.
     - In the Workflow Visualizer, Stage 5 shows **❌ FAILED: Authentication Tag Mismatch**, and Stages 6 & 7 are aborted.
   - Send another normal message immediately afterwards: it decrypts cleanly, proving that session state was not corrupted.

6. **Offline Store-and-Forward Relay:**
   - Close Bob's browser window. Alice's window reflects Bob as Offline.
   - Alice sends an encrypted message: status shows single checkmark `✓` (queued offline in SQLite).
   - Re-open Bob's incognito window and sign in: Bob immediately receives the queued envelope, decrypts it, and sends an acknowledgement removing it from the server queue.

## 6. Running Automated Tests

Open a second PowerShell terminal in `CN_updated`:

```powershell
Set-Location "C:\Users\pjasw\OneDrive\Desktop\End_to_End_Encrypted_Chat_Application_Updated\CN_updated"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1

# Run backend Python tests (16 tests covering API, Auth, DB, Relay, and Crypto):
.\venv\Scripts\python.exe -m pytest -v

# Run frontend Web Crypto API tests (6 tests covering Ratchet, Tamper rejection, Key agreement, Utilities):
node --test frontend\tests\crypto.test.js frontend\tests\e2e_crypto_integration.test.js
```

All 22 automated tests should pass with 100% success.
