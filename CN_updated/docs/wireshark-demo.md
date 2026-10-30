# Wireshark Demo for CypherChat

This guide explains how to capture the application traffic for the classroom demonstration without claiming that a browser can directly control Wireshark. The app runs locally by default on port `8000` and exposes a WebSocket endpoint at `ws://127.0.0.1:8000/ws` in development (`wss://...` when TLS is configured for production or a reverse proxy).

## 1. Start the app

From PowerShell:

```powershell
Set-Location "C:\Users\pjasw\OneDrive\Desktop\End_to_End_Encrypted_Chat_Application_Updated\CN_updated"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
$env:JWT_SECRET_KEY = [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Then open the app in a browser at `http://127.0.0.1:8000/`.

## 2. Start Wireshark

1. Launch Wireshark.
2. Select the active interface that carries loopback or local LAN traffic (for local testing, `Loopback` or the relevant adapter is usually correct).
3. Start a capture.
4. Log in with two demo users in separate browser sessions (for example, `alice` and `bob`).
5. Open a conversation and send a test message with a unique marker such as `demo-traffic-001`.

## 3. Useful display filters

Use these to narrow the traffic:

```text
tcp.port == 8000
http or websocket
tcp.stream
ip.addr == 127.0.0.1
ws
```

A practical capture flow is:

```text
tcp.port == 8000 and ip.addr == 127.0.0.1
```

## 4. What to look for

1. The TLS or plaintext HTTP/WebSocket connection is created on port `8000`.
2. The application uses a WebSocket handshake for `/ws`.
3. The browser sends JSON frames over the WebSocket connection, not raw chat text.
4. The actual message body inside the encrypted envelope is ciphertext, nonce, ratchet metadata, and a message identifier.
5. If the app is served over TLS behind a reverse proxy or secure deployment, Wireshark will show TLS records rather than readable WebSocket payloads.

## 5. Why the payload is protected

The backend only sees a JSON envelope such as:

```json
{
  "type": "send_encrypted_message",
  "payload": {
    "message_id": "demo-traffic-001",
    "recipient": "bob",
    "ciphertext": "<base64 ciphertext>",
    "iv": "<12-byte nonce>",
    "dh_ratchet_pubkey": "{...public JWK...}",
    "msg_counter": 0,
    "timestamp": 1720000000000
  }
}
```

The plain-text message itself is not in the network envelope. The sender and recipient browsers derive session keys locally with ECDH and HKDF, and the message is authenticated with AES-256-GCM. This means the relay can route the message without handling the plaintext or private keys.

## 6. Important distinction

- Client-side plaintext: visible only in the sender and recipient browser memory.
- Encrypted application payload: visible on the wire as ciphertext, nonces, and metadata.
- TLS/WSS traffic: protects the connection itself, but does not remove need for end-to-end encryption.

A Wireshark capture can show encrypted-looking bytes or TLS records, but that alone does not prove the full system is secure. The security claim is tied to the correctness of the browser-side E2EE implementation, key verification, and authenticated decryption logic.

## 7. Demo script

1. Start the app and log in as two users.
2. Open Wireshark and capture on the correct adapter.
3. Apply the filter `tcp.port == 8000`.
4. Send a unique test message from Alice to Bob.
5. Identify the WebSocket connection and the encrypted envelope around the `send_encrypted_message` event.
6. Explain that the payload is encrypted and the server does not read plaintext.
7. Note that a WSS capture may show TLS records instead of decoded frames, which is expected and correct.

This demonstration is intentionally conservative: it confirms what is visible on the network and differentiates transport-layer security from end-to-end message encryption.
