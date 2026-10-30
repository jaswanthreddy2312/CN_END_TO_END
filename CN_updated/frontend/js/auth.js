/**
 * Authentication & Key Registration Module
 */

const Auth = {
    tokenKey: 'e2ee_chat_token',
    userKey: 'e2ee_chat_username',

    getToken() {
        return sessionStorage.getItem(this.tokenKey) || localStorage.getItem(this.tokenKey);
    },

    getUsername() {
        return sessionStorage.getItem(this.userKey) || localStorage.getItem(this.userKey);
    },

    setAuth(token, username, remember = false) {
        const storage = remember ? localStorage : sessionStorage;
        storage.setItem(this.tokenKey, token);
        storage.setItem(this.userKey, username);
    },

    clearAuth() {
        sessionStorage.removeItem(this.tokenKey);
        sessionStorage.removeItem(this.userKey);
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.userKey);
    },

    async checkAuth() {
        const token = this.getToken();
        if (!token) return null;

        try {
            const res = await fetch('/api/auth/me', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                const user = await res.json();
                return user;
            } else {
                this.clearAuth();
                return null;
            }
        } catch (err) {
            console.error('Auth verification error:', err);
            return null;
        }
    },

    async register(username, password) {
        // 1. Generate client-side ECDH Identity & Prekey pairs
        // Notice: Private keys STAY securely on client device!
        let keys;
        let repairStoredKeys = false;
        try {
            keys = await window.e2eeCrypto.getUserKeys(username);
        } catch (error) {
            if (error.name !== 'InvalidStoredKeyRecordError') throw error;
            keys = await window.e2eeCrypto.generateUserKeys(username, false);
            repairStoredKeys = true;
        }
        const signedBundle = await window.e2eeCrypto.buildSignedPrekeyBundle(username, keys);

        const payload = {
            username: username.trim(),
            password: password,
            identity_pubkey: JSON.stringify({ ...keys.ik_pub_jwk, signing_pubkey: keys.signing_pub_jwk }),
            prekey_pubkey: JSON.stringify(keys.spk_pub_jwk),
            signed_prekey_pubkey: signedBundle.signed_prekey_pubkey,
            signed_prekey_signature: signedBundle.signed_prekey_signature,
            signature_algorithm: signedBundle.signature_algorithm
        };

        const res = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || 'Registration failed');
        }

        if (repairStoredKeys) {
            window.e2eeCrypto.saveUserKeys(username, keys);
        }
        this.setAuth(data.access_token, data.username);
        return data;
    },

    async login(username, password, remember = false) {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: username.trim(),
                password: password
            })
        });

        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || 'Login failed');
        }

        // Ensure cryptographic keys exist on this device for the logged-in user
        await window.e2eeCrypto.getUserKeys(data.username);

        this.setAuth(data.access_token, data.username, remember);
        return data;
    },

    async logout() {
        const token = this.getToken();
        if (token) {
            try {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${token}` }
                });
            } catch (e) {
                // Ignore network errors on logout
            }
        }
        this.clearAuth();
        window.location.reload();
    }
};

window.Auth = Auth;
