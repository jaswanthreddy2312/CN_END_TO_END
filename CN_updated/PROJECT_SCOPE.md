# Project Scope: End-to-End Encrypted Chat Application

## 1. Project title
**End-to-End Encrypted Chat Application: Develop a chat application with end-to-end encryption, forward secrecy, and message authentication to safeguard user privacy.**

## 2. Aim
To build a browser-based chat prototype in which message content is encrypted by the sender and decrypted by the intended recipient, while the server performs account management and message delivery without handling plaintext messages.

## 3. Objectives
1. Provide user registration and login.
2. Generate client-side cryptographic identity/prekey pairs.
3. Derive shared cryptographic material using ECDH and HKDF.
4. Encrypt messages using AES-256-GCM before transmission.
5. Detect message modification through authenticated decryption.
6. Demonstrate ratchet-style key evolution and explain forward-secrecy limitations.
7. Relay messages in real time and queue encrypted messages for offline recipients.
8. Validate envelope fields and bind the sender to the authenticated connection.
9. Provide a safety number for out-of-band contact-key verification.
10. Test authentication, APIs, user management, message relay, and crypto behavior.

## 4. Modules and source files

| Module | Main files | Responsibility |
|---|---|---|
| Frontend user interface | `frontend/index.html`, `frontend/css/styles.css` | Registration/login screens and chat layout |
| Authentication UI | `frontend/js/auth.js` | Registration, login, token handling, API requests |
| Chat and delivery | `frontend/js/chat.js` | Contacts, conversations, WebSocket communication, message status and rendering |
| Client cryptography | `frontend/js/crypto.js` | ECDH, HKDF, AES-GCM encryption/decryption, ratchet-style state, safety numbers |
| Backend application | `backend/app/main.py` | FastAPI application, startup and static frontend serving |
| Authentication/security | `backend/app/auth.py`, `backend/app/security.py` | Registration/login routes, Argon2id password hashing, JWT creation/validation, login lockout |
| User/key directory | `backend/app/users.py` | User profiles and public key bundle endpoints |
| Data models/validation | `backend/app/models.py` | Request schemas and encrypted-envelope validation |
| WebSocket connection manager | `backend/app/websocket_manager.py` | Active connections and online presence |
| WebSocket relay | `backend/app/websocket_router.py` | Authenticated real-time message routing and acknowledgements |
| Offline message queue | `backend/app/message_relay.py` | Store-and-forward of encrypted envelopes |
| Database | `backend/app/database.py` | SQLite connection and table initialization |
| Configuration | `backend/app/config.py` | Application settings and token configuration |
| Automated tests | `backend/tests/`, `frontend/tests/crypto.test.js` | API, authentication, relay, and cryptography tests |

## 5. How a message is protected
1. The sender signs in and opens a conversation with a recipient.
2. The clients obtain public identity/prekey information from the server.
3. The sender's browser derives session material using ECDH and HKDF.
4. The sender's browser derives a message key and encrypts the message using AES-256-GCM with a fresh 12-byte nonce.
5. The browser sends an envelope containing ciphertext, nonce, recipient, counters, and public ratchet metadata.
6. The server authenticates the WebSocket connection, validates the envelope, and relays or queues it. It does not need the plaintext or message key.
7. The recipient's browser derives the corresponding key and attempts authenticated decryption.
8. If the ciphertext or authentication tag is modified, AES-GCM decryption fails and the message must not be shown as valid plaintext.
9. The recipient acknowledges delivery, allowing the server to remove the queued envelope.
10. Users can compare safety numbers out of band to help detect key substitution.

## 6. Demonstration checklist
- Register two different users in two separate browser sessions (normal and private/incognito windows).
- Log in as both users and confirm both appear in the contact/user list.
- Start a conversation and send a normal message in each direction.
- Verify the recipient sees the original plaintext only after client-side decryption.
- Send a message while the recipient is disconnected, then reconnect and verify queued delivery.
- Use the available tamper demonstration, if exposed by the UI, and confirm the altered message fails authentication rather than being accepted.
- Compare safety numbers in both sessions through a separate trusted channel.
- Run the backend and frontend crypto test commands in `START_HERE_WINDOWS.md`.

## 7. Security claims and limitations
The current code is an educational prototype, not an audited production messenger. AES-GCM provides ciphertext integrity/authentication when used correctly. Client-side encryption keeps message plaintext out of the relay server's message envelope. However, the custom ratchet is not a reviewed Signal Protocol implementation and **full forward secrecy is not independently verified or guaranteed**. Private identity keys and ratchet state are currently serialized into browser `localStorage`; the static prekey is reused; key bundles are not authenticated by signatures; metadata is visible to the server; and skipped-message recovery/session-reset behavior is limited.

Therefore, in a report or viva, describe forward secrecy as a design objective and ratchet concept demonstrated by the prototype, not as a production-grade guarantee. A production implementation should use a maintained, audited E2EE protocol library, signed and one-time prekeys as appropriate, authenticated key verification, secure key storage, TLS/WSS, and a professional security review.
