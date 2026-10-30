/**
 * Client-Side Cryptographic Engine for End-to-End Encrypted Chat
 * 
 * Standards & Primitives:
 * - ECDH: Curve P-256 (NIST secp256r1) for Key Exchange & Asymmetric Ratchet
 * - HKDF: HKDF-SHA-256 (RFC 5869) for Key Derivation & Symmetric Ratchet Chaining
 * - AEAD: AES-256-GCM (NIST SP 800-38D) with 12-byte unique nonces & 128-bit authentication tags
 * - CSPRNG: crypto.getRandomValues()
 * - Safety Numbers: SHA-256 Fingerprint matching
 * 
 * This is an educational, custom ratchet-style prototype, not a reviewed Signal
 * Protocol implementation. See README.md for its security limitations.
 */

class E2EECrypto {
    constructor() {
        this.subtle = window.crypto.subtle;
    }

    // -------------------------------------------------------------
    // Utility Encoders & Decoders
    // -------------------------------------------------------------

    buf2b64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    b642buf(base64) {
        const binary_string = window.atob(base64);
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    }

    encodeUtf8(str) {
        return new TextEncoder().encode(str);
    }

    decodeUtf8(buf) {
        return new TextDecoder().decode(buf);
    }

    buf2hex(buffer) {
        if (!buffer) return '';
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        const hex = [];
        for (let i = 0; i < bytes.length; i++) {
            hex.push(bytes[i].toString(16).padStart(2, '0'));
        }
        return hex.join(' ');
    }

    buf2hexCompact(buffer) {
        if (!buffer) return '';
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        let hex = '';
        for (let i = 0; i < bytes.length; i++) {
            hex += bytes[i].toString(16).padStart(2, '0');
        }
        return hex;
    }

    bytesToBase64Url(bytes) {
        const uint8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        let binary = '';
        for (let i = 0; i < uint8.length; i++) {
            binary += String.fromCharCode(uint8[i]);
        }
        return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    base64UrlToBytes(str) {
        const normalized = str.replace(/-/g, '+').replace(/_/g, '/');
        const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
        const binary = window.atob(normalized + pad);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    isValidP256Jwk(jwk) {
        if (!jwk || typeof jwk !== 'object') return false;
        return jwk.kty === 'EC' && jwk.crv === 'P-256' && typeof jwk.x === 'string' && typeof jwk.y === 'string' && !('d' in jwk || 'private' in jwk);
    }

    isValidP256PrivateJwk(jwk) {
        return Boolean(
            jwk &&
            typeof jwk === 'object' &&
            jwk.kty === 'EC' &&
            jwk.crv === 'P-256' &&
            typeof jwk.x === 'string' &&
            typeof jwk.y === 'string' &&
            typeof jwk.d === 'string'
        );
    }

    requireP256PublicJwk(jwk) {
        if (!this.isValidP256Jwk(jwk)) {
            throw new TypeError('Expected an EC P-256 public JWK containing kty, crv, x, and y.');
        }
    }

    requireP256PrivateJwk(jwk) {
        if (!this.isValidP256PrivateJwk(jwk)) {
            throw new TypeError('Expected an EC P-256 private JWK containing kty, crv, x, y, and d.');
        }
    }

    async signObjectWithPrivateKey(privateKey, payloadObj) {
        if (
            !privateKey ||
            privateKey.type !== 'private' ||
            privateKey.algorithm.name !== 'ECDSA' ||
            privateKey.algorithm.namedCurve !== 'P-256' ||
            !privateKey.usages.includes('sign')
        ) {
            throw new TypeError('Expected an ECDSA P-256 private CryptoKey with signing permission.');
        }
        const payloadBytes = this.encodeUtf8(JSON.stringify(payloadObj));
        const sig = await this.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, payloadBytes);
        return this.bytesToBase64Url(new Uint8Array(sig));
    }

    async verifySignedPrekey(identityPublicJwk, prekeyPublicJwk, signatureB64) {
        if (!this.isValidP256Jwk(identityPublicJwk) || !this.isValidP256Jwk(prekeyPublicJwk) || !signatureB64) {
            return { valid: false, reason: 'Missing or malformed identity/prekey material.' };
        }
        try {
            const signerJwk = identityPublicJwk.signing_pubkey || identityPublicJwk;
            const identityKey = await this.importECDSAPublicKeyJwk(signerJwk);
            const sigBytes = this.base64UrlToBytes(signatureB64);
            const payloadBytes = this.encodeUtf8(JSON.stringify(prekeyPublicJwk));
            const ok = await this.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, identityKey, sigBytes, payloadBytes);
            return ok ? { valid: true, reason: 'Signature verified successfully.' } : { valid: false, reason: 'Signature verification failed.' };
        } catch (err) {
            return { valid: false, reason: err && err.message ? err.message : 'Invalid signature or malformed key material.' };
        }
    }

    async validatePeerIdentityBundle(identityPublicJwk, signedPrekeyJwk, signatureB64, peerName = 'contact') {
        if (!identityPublicJwk || !signedPrekeyJwk || !signatureB64) {
            throw new Error(`Identity verification for ${peerName} failed: Missing signed key bundle.`);
        }

        const result = await this.verifySignedPrekey(
            typeof identityPublicJwk === 'string' ? JSON.parse(identityPublicJwk) : identityPublicJwk,
            typeof signedPrekeyJwk === 'string' ? JSON.parse(signedPrekeyJwk) : signedPrekeyJwk,
            signatureB64
        );

        if (!result.valid) {
            throw new Error(`Identity verification for ${peerName} failed: ${result.reason}`);
        }

        return result;
    }

    async buildSignedPrekeyBundle(username, userKeys = null) {
        const keys = userKeys || await this.getUserKeys(username);
        const signedPrekey = {
            ...keys.spk_pub_jwk,
            kid: `spk-${String(username).trim().toLowerCase()}`
        };
        const signature = await this.signObjectWithPrivateKey(keys.signing_priv, signedPrekey);
        return {
            identity_pubkey: JSON.stringify({ ...keys.ik_pub_jwk, signing_pubkey: keys.signing_pub_jwk }),
            prekey_pubkey: JSON.stringify(keys.spk_pub_jwk),
            signed_prekey_pubkey: JSON.stringify(signedPrekey),
            signed_prekey_signature: signature,
            signature_algorithm: 'ECDSA-P-256-SHA256'
        };
    }

    extractAuthTagHex(ciphertextBase64) {
        try {
            const buf = this.b642buf(ciphertextBase64);
            const bytes = new Uint8Array(buf);
            if (bytes.length >= 16) {
                const tag = bytes.slice(bytes.length - 16);
                return this.buf2hex(tag);
            }
            return 'N/A';
        } catch {
            return 'Invalid';
        }
    }

    extractCiphertextHex(ciphertextBase64) {
        try {
            const buf = this.b642buf(ciphertextBase64);
            const bytes = new Uint8Array(buf);
            if (bytes.length > 16) {
                const ct = bytes.slice(0, bytes.length - 16);
                return this.buf2hex(ct);
            }
            return '';
        } catch {
            return 'Invalid';
        }
    }

    extractNonceHex(ivBase64) {
        try {
            const buf = this.b642buf(ivBase64);
            return this.buf2hex(buf);
        } catch {
            return 'Invalid';
        }
    }

    // -------------------------------------------------------------
    // Key Generation, Import & Export
    // -------------------------------------------------------------

    async generateECDHKeyPair() {
        return await this.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveBits"]
        );
    }

    async generateECDSAKeyPair() {
        return await this.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["sign", "verify"]
        );
    }

    async exportKeyJwk(key) {
        return await this.subtle.exportKey("jwk", key);
    }

    async importPublicKeyJwk(jwk) {
        this.requireP256PublicJwk(jwk);
        return await this.subtle.importKey(
            "jwk",
            jwk,
            { name: "ECDH", namedCurve: "P-256" },
            true,
            []
        );
    }

    async importPrivateKeyJwk(jwk) {
        this.requireP256PrivateJwk(jwk);
        return await this.subtle.importKey(
            "jwk",
            jwk,
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveBits"]
        );
    }

    async importECDSAPublicKeyJwk(jwk) {
        this.requireP256PublicJwk(jwk);
        return await this.subtle.importKey(
            "jwk",
            jwk,
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["verify"]
        );
    }

    async importECDSAPrivateKeyJwk(jwk) {
        this.requireP256PrivateJwk(jwk);
        return await this.subtle.importKey(
            "jwk",
            jwk,
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["sign"]
        );
    }

    // -------------------------------------------------------------
    // Key Derivation Functions (ECDH & HKDF)
    // -------------------------------------------------------------

    async computeECDH(privateKey, remotePublicKey) {
        const bits = await this.subtle.deriveBits(
            { name: "ECDH", public: remotePublicKey },
            privateKey,
            256
        );
        return new Uint8Array(bits);
    }

    async hkdfDerive(ikmBytes, saltBytes, infoStr, lengthBytes = 32) {
        const hkdfKey = await this.subtle.importKey(
            "raw",
            ikmBytes,
            { name: "HKDF" },
            false,
            ["deriveBits"]
        );
        const salt = saltBytes || new Uint8Array(32);
        const info = this.encodeUtf8(infoStr);
        const bits = await this.subtle.deriveBits(
            { name: "HKDF", hash: "SHA-256", salt: salt, info: info },
            hkdfKey,
            lengthBytes * 8
        );
        return new Uint8Array(bits);
    }

    // -------------------------------------------------------------
    // Identity Key Management & Safety Numbers
    // -------------------------------------------------------------

    async getUserKeys(username) {
        const storageKey = `e2ee_keys_${username.toLowerCase()}`;
        const stored = localStorage.getItem(storageKey);
        if (stored) {
            try {
                const data = JSON.parse(stored);
                const ikPriv = await this.importPrivateKeyJwk(data.ik_priv);
                const ikPub = await this.importPublicKeyJwk(data.ik_pub);
                const spkPriv = await this.importPrivateKeyJwk(data.spk_priv);
                const spkPub = await this.importPublicKeyJwk(data.spk_pub);
                const signingPriv = await this.importECDSAPrivateKeyJwk(data.signing_priv);
                const signingPub = await this.importECDSAPublicKeyJwk(data.signing_pub);
                return {
                    ik_priv: ikPriv,
                    ik_pub: ikPub,
                    spk_priv: spkPriv,
                    spk_pub: spkPub,
                    signing_priv: signingPriv,
                    signing_pub: signingPub,
                    ik_priv_jwk: data.ik_priv,
                    ik_pub_jwk: data.ik_pub,
                    spk_priv_jwk: data.spk_priv,
                    spk_pub_jwk: data.spk_pub,
                    signing_priv_jwk: data.signing_priv,
                    signing_pub_jwk: data.signing_pub
                };
            } catch (cause) {
                const error = new Error('Stored cryptographic key record is invalid.', { cause });
                error.name = 'InvalidStoredKeyRecordError';
                throw error;
            }
        }

        return await this.generateUserKeys(username);
    }

    async generateUserKeys(username, persist = true) {
        // Generate fresh Identity Key and Prekey pairs
        const ikPair = await this.generateECDHKeyPair();
        const spkPair = await this.generateECDHKeyPair();
        const signingPair = await this.generateECDSAKeyPair();

        const ikPubJwk = await this.exportKeyJwk(ikPair.publicKey);
        const ikPrivJwk = await this.exportKeyJwk(ikPair.privateKey);
        const spkPubJwk = await this.exportKeyJwk(spkPair.publicKey);
        const spkPrivJwk = await this.exportKeyJwk(spkPair.privateKey);
        const signingPubJwk = await this.exportKeyJwk(signingPair.publicKey);
        const signingPrivJwk = await this.exportKeyJwk(signingPair.privateKey);

        const record = {
            ik_priv: ikPrivJwk,
            ik_pub: ikPubJwk,
            spk_priv: spkPrivJwk,
            spk_pub: spkPubJwk,
            signing_priv: signingPrivJwk,
            signing_pub: signingPubJwk
        };
        if (persist) {
            localStorage.setItem(`e2ee_keys_${username.toLowerCase()}`, JSON.stringify(record));
        }

        return {
            ik_priv: ikPair.privateKey,
            ik_pub: ikPair.publicKey,
            spk_priv: spkPair.privateKey,
            spk_pub: spkPair.publicKey,
            signing_priv: signingPair.privateKey,
            signing_pub: signingPair.publicKey,
            ik_priv_jwk: ikPrivJwk,
            ik_pub_jwk: ikPubJwk,
            spk_priv_jwk: spkPrivJwk,
            spk_pub_jwk: spkPubJwk,
            signing_priv_jwk: signingPrivJwk,
            signing_pub_jwk: signingPubJwk
        };
    }

    saveUserKeys(username, keys) {
        const record = {
            ik_priv: keys.ik_priv_jwk,
            ik_pub: keys.ik_pub_jwk,
            spk_priv: keys.spk_priv_jwk,
            spk_pub: keys.spk_pub_jwk,
            signing_priv: keys.signing_priv_jwk,
            signing_pub: keys.signing_pub_jwk
        };
        localStorage.setItem(`e2ee_keys_${username.toLowerCase()}`, JSON.stringify(record));
    }

    async computeSafetyNumber(pubA_Jwk, pubB_Jwk) {
        const strA = JSON.stringify(pubA_Jwk);
        const strB = JSON.stringify(pubB_Jwk);

        const hashABuf = await this.subtle.digest("SHA-256", this.encodeUtf8(strA));
        const hashBBuf = await this.subtle.digest("SHA-256", this.encodeUtf8(strB));

        const hexA = this.buf2b64(hashABuf);
        const hexB = this.buf2b64(hashBBuf);

        // Sort lexicographically to ensure order-independence
        const combined = hexA < hexB ? (hexA + hexB) : (hexB + hexA);
        const finalBuf = await this.subtle.digest("SHA-256", this.encodeUtf8(combined));
        const finalBytes = new Uint8Array(finalBuf);

        // Derive 6 blocks of 5 digits
        const blocks = [];
        for (let i = 0; i < 12; i += 2) {
            const val = ((finalBytes[i] << 8) | finalBytes[i + 1]) % 100000;
            blocks.push(String(val).padStart(5, '0'));
        }
        return blocks.join(' ');
    }

    // -------------------------------------------------------------
    // Session State Management
    // -------------------------------------------------------------

    getSessionKey(myUsername, peerUsername) {
        const local = myUsername.toLowerCase();
        const peer = peerUsername.toLowerCase();
        return `e2ee_session_${local.length}:${local}${peer.length}:${peer}`;
    }

    getLegacySessionKey(myUsername, peerUsername) {
        return `e2ee_session_${myUsername.toLowerCase()}_${peerUsername.toLowerCase()}`;
    }

    loadSession(myUsername, peerUsername) {
        const key = this.getSessionKey(myUsername, peerUsername);
        const legacyKey = this.getLegacySessionKey(myUsername, peerUsername);
        const data = localStorage.getItem(key) || localStorage.getItem(legacyKey);
        if (data && !localStorage.getItem(key)) {
            localStorage.setItem(key, data);
            localStorage.removeItem(legacyKey);
        }
        return data ? JSON.parse(data) : null;
    }

    saveSession(myUsername, peerUsername, session) {
        localStorage.setItem(this.getSessionKey(myUsername, peerUsername), JSON.stringify(session));
        localStorage.removeItem(this.getLegacySessionKey(myUsername, peerUsername));
    }

    removeSession(myUsername, peerUsername) {
        localStorage.removeItem(this.getSessionKey(myUsername, peerUsername));
        localStorage.removeItem(this.getLegacySessionKey(myUsername, peerUsername));
    }

    // -------------------------------------------------------------
    // Session Initialization (X3DH Key Agreement)
    // -------------------------------------------------------------

    async initializeOutboundSession(myUsername, peerUsername, peerIkJwk, peerSpkJwk, signedPrekeyJwk = null, signedPrekeySignature = null) {
        if (signedPrekeyJwk || signedPrekeySignature) {
            if (!signedPrekeyJwk || !signedPrekeySignature) {
                throw new Error(`Identity verification for ${peerUsername} failed: Signed prekey metadata is incomplete.`);
            }
            await this.validatePeerIdentityBundle(
                peerIkJwk,
                signedPrekeyJwk,
                signedPrekeySignature,
                peerUsername
            );
        }

        const myKeys = await this.getUserKeys(myUsername);
        const peerIk = await this.importPublicKeyJwk(peerIkJwk);
        const peerSpk = await this.importPublicKeyJwk(peerSpkJwk);

        // 1. Generate Ephemeral Key Pair EK_A
        const ekPair = await this.generateECDHKeyPair();
        const ekPubJwk = await this.exportKeyJwk(ekPair.publicKey);

        // 2. Generate initial DH Ratchet Key Pair DHK_A0
        const dhPair = await this.generateECDHKeyPair();
        const dhPubJwk = await this.exportKeyJwk(dhPair.publicKey);
        const dhPrivJwk = await this.exportKeyJwk(dhPair.privateKey);

        // 3. Compute X3DH shared secrets:
        // DH1 = ECDH(IK_A, SPK_B)
        const dh1 = await this.computeECDH(myKeys.ik_priv, peerSpk);
        // DH2 = ECDH(EK_A, IK_B)
        const dh2 = await this.computeECDH(ekPair.privateKey, peerIk);
        // DH3 = ECDH(EK_A, SPK_B)
        const dh3 = await this.computeECDH(ekPair.privateKey, peerSpk);

        // Combine secrets
        const total = new Uint8Array(dh1.length + dh2.length + dh3.length);
        total.set(dh1, 0);
        total.set(dh2, dh1.length);
        total.set(dh3, dh1.length + dh2.length);

        // Derive initial Root Key (SK)
        const sk = await this.hkdfDerive(
            total,
            this.encodeUtf8("E2EE_X3DH_SALT_V1"),
            "WhisperRatchetRootKey",
            32
        );

        // Initial DH Ratchet step with peer's prekey
        const dhRatchet = await this.computeECDH(dhPair.privateKey, peerSpk);
        const stepOut = await this.hkdfDerive(
            dhRatchet,
            sk,
            "WhisperRatchetStep",
            64
        );
        const newRootKey = stepOut.slice(0, 32);
        const sendingChainKey = stepOut.slice(32, 64);

        const safetyNumber = await this.computeSafetyNumber(myKeys.ik_pub_jwk, peerIkJwk);

        const session = {
            peerUsername: peerUsername.toLowerCase(),
            rootKey: this.buf2b64(newRootKey),
            sendingChainKey: this.buf2b64(sendingChainKey),
            receivingChainKey: null,
            dhPair: { pub: dhPubJwk, priv: dhPrivJwk },
            remoteDhPub: peerSpkJwk,
            sendCounter: 0,
            recvCounter: 0,
            prevChainLen: 0,
            safetyNumber: safetyNumber,
            isInitiator: true,
            peerIkJwk: peerIkJwk
        };

        this.saveSession(myUsername, peerUsername, session);

        return {
            session,
            handshake: {
                ephemeral_pubkey: JSON.stringify(ekPubJwk),
                dh_ratchet_pubkey: JSON.stringify(dhPubJwk)
            }
        };
    }

    async initializeInboundSession(myUsername, peerUsername, peerIkJwk, handshakeData) {
        const myKeys = await this.getUserKeys(myUsername);
        const peerIk = await this.importPublicKeyJwk(peerIkJwk);
        const peerEk = await this.importPublicKeyJwk(JSON.parse(handshakeData.ephemeral_pubkey));
        const senderDhk = await this.importPublicKeyJwk(JSON.parse(handshakeData.dh_ratchet_pubkey));

        // Matching X3DH calculations:
        // DH1 = ECDH(SPK_B, IK_A)
        const dh1 = await this.computeECDH(myKeys.spk_priv, peerIk);
        // DH2 = ECDH(IK_B, EK_A)
        const dh2 = await this.computeECDH(myKeys.ik_priv, peerEk);
        // DH3 = ECDH(SPK_B, EK_A)
        const dh3 = await this.computeECDH(myKeys.spk_priv, peerEk);

        const total = new Uint8Array(dh1.length + dh2.length + dh3.length);
        total.set(dh1, 0);
        total.set(dh2, dh1.length);
        total.set(dh3, dh1.length + dh2.length);

        const sk = await this.hkdfDerive(
            total,
            this.encodeUtf8("E2EE_X3DH_SALT_V1"),
            "WhisperRatchetRootKey",
            32
        );

        // Derive matching receiving chain key
        const dhRatchet = await this.computeECDH(myKeys.spk_priv, senderDhk);
        const stepOut = await this.hkdfDerive(
            dhRatchet,
            sk,
            "WhisperRatchetStep",
            64
        );
        const newRootKey = stepOut.slice(0, 32);
        const receivingChainKey = stepOut.slice(32, 64);

        const safetyNumber = await this.computeSafetyNumber(myKeys.ik_pub_jwk, peerIkJwk);

        // Setup local DH pair (using SPK initially)
        const spkPubJwk = await this.exportKeyJwk(myKeys.spk_pub);
        const spkPrivJwk = await this.exportKeyJwk(myKeys.spk_priv);

        const session = {
            peerUsername: peerUsername.toLowerCase(),
            rootKey: this.buf2b64(newRootKey),
            sendingChainKey: null,
            receivingChainKey: this.buf2b64(receivingChainKey),
            dhPair: { pub: spkPubJwk, priv: spkPrivJwk },
            remoteDhPub: JSON.parse(handshakeData.dh_ratchet_pubkey),
            sendCounter: 0,
            recvCounter: 0,
            prevChainLen: 0,
            safetyNumber: safetyNumber,
            isInitiator: false,
            peerIkJwk: peerIkJwk
        };

        return session;
    }

    // -------------------------------------------------------------
    // Double Ratchet Message Encryption
    // -------------------------------------------------------------

    async encrypt(myUsername, peerUsername, plaintext, isTamperDemo = false) {
        let session = this.loadSession(myUsername, peerUsername);
        if (!session) {
            throw new Error(`Cannot encrypt: No active E2EE session exists with '${peerUsername}'. Handshake required.`);
        }

        // If sendingChainKey is missing, we need an Asymmetric DH Ratchet step
        if (!session.sendingChainKey) {
            const newDhPair = await this.generateECDHKeyPair();
            const newDhPubJwk = await this.exportKeyJwk(newDhPair.publicKey);
            const newDhPrivJwk = await this.exportKeyJwk(newDhPair.privateKey);

            const remoteDhKey = await this.importPublicKeyJwk(session.remoteDhPub);
            const dhSecret = await this.computeECDH(newDhPair.privateKey, remoteDhKey);

            const rootBytes = new Uint8Array(this.b642buf(session.rootKey));
            const stepOut = await this.hkdfDerive(dhSecret, rootBytes, "WhisperRatchetStep", 64);

            session.rootKey = this.buf2b64(stepOut.slice(0, 32));
            session.sendingChainKey = this.buf2b64(stepOut.slice(32, 64));
            session.prevChainLen = session.sendCounter;
            session.sendCounter = 0;
            session.dhPair = { pub: newDhPubJwk, priv: newDhPrivJwk };
        }

        // Symmetric chain step:
        // Derive message key MK from sendingChainKey
        const currentChainBytes = new Uint8Array(this.b642buf(session.sendingChainKey));
        const mkBytes = await this.hkdfDerive(currentChainBytes, null, "MessageKey", 32);

        // Advance the sending chain; this alone does not establish full forward secrecy.
        const nextChainBytes = await this.hkdfDerive(currentChainBytes, null, "ChainAdvance", 32);
        session.sendingChainKey = this.buf2b64(nextChainBytes);

        // AES-256-GCM authenticated encryption
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const aesKey = await this.subtle.importKey(
            "raw",
            mkBytes,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
        );

        const plaintextBytes = this.encodeUtf8(plaintext);
        let ciphertextBuffer = await this.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            plaintextBytes
        );

        // If tamper simulation requested, flip bits in ciphertext, tag, or nonce
        if (isTamperDemo === 'iv') {
            iv[0] ^= 0x01; // Corrupt IV/nonce byte
        } else if (isTamperDemo === 'tag') {
            const ctBytes = new Uint8Array(ciphertextBuffer);
            ctBytes[ctBytes.length - 1] ^= 0xAA; // Corrupt authentication tag byte
            ciphertextBuffer = ctBytes.buffer;
        } else if (isTamperDemo) {
            const ctBytes = new Uint8Array(ciphertextBuffer);
            ctBytes[0] ^= 0xFF; // Corrupt ciphertext byte
            ciphertextBuffer = ctBytes.buffer;
        }

        const msgCounter = session.sendCounter;
        session.sendCounter += 1;

        // Persist session state (Message Key MK is now completely discarded!)
        if (!isTamperDemo) {
            this.saveSession(myUsername, peerUsername, session);
        }

        const envelope = {
            message_id: 'msg_' + window.crypto.randomUUID(),
            recipient: peerUsername,
            ciphertext: this.buf2b64(ciphertextBuffer),
            iv: this.buf2b64(iv),
            dh_ratchet_pubkey: JSON.stringify(session.dhPair.pub),
            msg_counter: msgCounter,
            prev_chain_len: session.prevChainLen,
            timestamp: Date.now(),
            is_initial: false
        };

        this.lastEncryptionDiagnostics = {
            plaintext,
            sender: myUsername,
            recipient: peerUsername,
            ivBase64: envelope.iv,
            ivHex: this.buf2hex(iv),
            ciphertextBase64: envelope.ciphertext,
            ciphertextHex: this.extractCiphertextHex(envelope.ciphertext),
            authTagHex: this.extractAuthTagHex(envelope.ciphertext),
            msgCounter: msgCounter,
            dhRatchetPubkey: session.dhPair.pub,
            timestamp: envelope.timestamp,
            isTampered: !!isTamperDemo,
            tamperType: typeof isTamperDemo === 'string' ? isTamperDemo : (isTamperDemo ? 'ciphertext' : null),
            status: isTamperDemo ? 'Tampered Envelope (Simulated Attack)' : 'AES-256-GCM Encrypted'
        };

        return envelope;
    }

    // -------------------------------------------------------------
    // Double Ratchet Message Decryption
    // -------------------------------------------------------------

    async decrypt(myUsername, peerUsername, envelope, peerIdentityJwk) {
        let session = this.loadSession(myUsername, peerUsername);

        // If no session exists and envelope is an initial handshake
        if (!session && envelope.is_initial) {
            session = await this.initializeInboundSession(myUsername, peerUsername, peerIdentityJwk, {
                ephemeral_pubkey: envelope.ephemeral_pubkey,
                dh_ratchet_pubkey: envelope.dh_ratchet_pubkey
            });
        } else if (!session) {
            throw new Error(`Session with ${peerUsername} not established.`);
        }

        const incomingDhJwk = JSON.parse(envelope.dh_ratchet_pubkey);
        const currentRemoteDhStr = JSON.stringify(session.remoteDhPub);
        const incomingDhStr = JSON.stringify(incomingDhJwk);

        // Check if Asymmetric DH Ratchet step is needed
        if (incomingDhStr !== currentRemoteDhStr) {
            session.remoteDhPub = incomingDhJwk;
            const remoteDhKey = await this.importPublicKeyJwk(incomingDhJwk);
            const myDhPriv = await this.importPrivateKeyJwk(session.dhPair.priv);

            const dhSecret = await this.computeECDH(myDhPriv, remoteDhKey);
            const rootBytes = new Uint8Array(this.b642buf(session.rootKey));

            const stepOut = await this.hkdfDerive(dhSecret, rootBytes, "WhisperRatchetStep", 64);
            session.rootKey = this.buf2b64(stepOut.slice(0, 32));
            session.receivingChainKey = this.buf2b64(stepOut.slice(32, 64));
            session.recvCounter = 0;
            // Sending chain will be renewed on next outbound reply
            session.sendingChainKey = null;
        }

        if (!session.receivingChainKey) {
            throw new Error("Invalid session state: missing receiving chain key.");
        }

        if (!Number.isInteger(envelope.msg_counter) || envelope.msg_counter !== session.recvCounter) {
            throw new Error("Replay or out-of-order message rejected; this prototype does not buffer skipped messages.");
        }

        // Symmetric chain step:
        const currentRecvChainBytes = new Uint8Array(this.b642buf(session.receivingChainKey));
        const mkBytes = await this.hkdfDerive(currentRecvChainBytes, null, "MessageKey", 32);

        // Advance the receiving chain. Skipped-message keys are not retained.
        const nextRecvChainBytes = await this.hkdfDerive(currentRecvChainBytes, null, "ChainAdvance", 32);
        session.receivingChainKey = this.buf2b64(nextRecvChainBytes);
        session.recvCounter += 1;

        // AES-256-GCM authenticated decryption
        const aesKey = await this.subtle.importKey(
            "raw",
            mkBytes,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        const iv = new Uint8Array(this.b642buf(envelope.iv));
        const ciphertext = this.b642buf(envelope.ciphertext);
        const nonceHex = this.buf2hex(iv);
        const authTagHex = this.extractAuthTagHex(envelope.ciphertext);
        const ciphertextHex = this.extractCiphertextHex(envelope.ciphertext);

        try {
            const decryptedBuf = await this.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                aesKey,
                ciphertext
            );
            // Save updated session state
            this.saveSession(myUsername, peerUsername, session);
            const decryptedText = this.decodeUtf8(decryptedBuf);

            this.lastDecryptionDiagnostics = {
                sender: peerUsername,
                recipient: myUsername,
                envelope,
                plaintext: decryptedText,
                ivHex: nonceHex,
                authTagHex: authTagHex,
                ciphertextHex: ciphertextHex,
                msgCounter: envelope.msg_counter,
                authStatus: 'PASSED',
                authDetails: 'AES-256-GCM 128-bit authentication tag verified successfully.',
                decryptionStatus: 'SUCCESS',
                isTampered: false
            };

            return decryptedText;
        } catch (err) {
            this.lastDecryptionDiagnostics = {
                sender: peerUsername,
                recipient: myUsername,
                envelope,
                plaintext: null,
                ivHex: nonceHex,
                authTagHex: authTagHex,
                ciphertextHex: ciphertextHex,
                msgCounter: envelope.msg_counter,
                authStatus: 'FAILED',
                authDetails: 'Authentication tag verification failed! The ciphertext or nonce was corrupted or tampered with in transit.',
                decryptionStatus: 'ABORTED',
                isTampered: true,
                error: err.message
            };
            // Revert or save session, and throw explicit security alert!
            throw new Error(`SECURITY ALERT: Authentication tag verification failed! The ciphertext was tampered with or corrupted on the wire.`);
        }
    }
}

// Global instance accessible to application
window.e2eeCrypto = new E2EECrypto();
