const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const { TextDecoder, TextEncoder } = require('node:util');

const storage = new Map();
const windowStub = {
    crypto: webcrypto,
    btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
    atob: (value) => Buffer.from(value, 'base64').toString('binary')
};
const context = vm.createContext({
    window: windowStub,
    TextDecoder,
    TextEncoder,
    localStorage: {
        getItem: (key) => storage.get(key) ?? null,
        setItem: (key, value) => storage.set(key, String(value)),
        removeItem: (key) => storage.delete(key)
    },
    sessionStorage: {
        setItem: () => {},
        getItem: () => null,
        removeItem: () => {}
    }
});

vm.runInContext(
    fs.readFileSync(path.join(__dirname, '..', 'js', 'crypto.js'), 'utf8'),
    context,
    { filename: 'crypto.js' }
);

const crypto = windowStub.e2eeCrypto;

test.beforeEach(() => storage.clear());

async function createInitialMessage(sender, recipient) {
    const recipientKeys = await crypto.getUserKeys(recipient);
    const init = await crypto.initializeOutboundSession(
        sender,
        recipient,
        recipientKeys.ik_pub_jwk,
        recipientKeys.spk_pub_jwk
    );
    const envelope = await crypto.encrypt(sender, recipient, 'initial secret');
    envelope.is_initial = true;
    envelope.ephemeral_pubkey = init.handshake.ephemeral_pubkey;
    return { envelope, senderIdentity: (await crypto.getUserKeys(sender)).ik_pub_jwk };
}

test('sessions are isolated across distinct and ambiguous-looking conversations', async () => {
    const bobKeys = await crypto.getUserKeys('bob');
    const carolKeys = await crypto.getUserKeys('carol');
    const bobSession = await crypto.initializeOutboundSession(
        'alice',
        'bob',
        bobKeys.ik_pub_jwk,
        bobKeys.spk_pub_jwk
    );
    const carolSession = await crypto.initializeOutboundSession(
        'alice',
        'carol',
        carolKeys.ik_pub_jwk,
        carolKeys.spk_pub_jwk
    );

    assert.notEqual(crypto.getSessionKey('alice_b', 'c'), crypto.getSessionKey('alice', 'b_c'));
    assert.notEqual(bobSession.session.rootKey, carolSession.session.rootKey);
});

test('initial exchange, tamper rejection, ordered delivery, and replay rejection use browser crypto', async () => {
    const { envelope, senderIdentity } = await createInitialMessage('alice', 'bob');
    const wireData = JSON.stringify(envelope);
    assert.equal(wireData.includes('initial secret'), false);
    assert.equal('d' in JSON.parse(envelope.dh_ratchet_pubkey), false);
    assert.equal('d' in JSON.parse(envelope.ephemeral_pubkey), false);
    assert.equal(
        await crypto.decrypt('bob', 'alice', envelope, senderIdentity),
        'initial secret'
    );

    const tampered = await crypto.encrypt('alice', 'bob', 'altered secret', true);
    await assert.rejects(
        crypto.decrypt('bob', 'alice', tampered, senderIdentity),
        /Authentication tag verification failed/
    );
    assert.equal(crypto.loadSession('bob', 'alice').recvCounter, 1);

    const next = await crypto.encrypt('alice', 'bob', 'valid after demo tamper');
    assert.equal(next.msg_counter, 1);
    assert.equal(
        await crypto.decrypt('bob', 'alice', next, senderIdentity),
        'valid after demo tamper'
    );
    assert.equal(crypto.loadSession('bob', 'alice').recvCounter, 2);

    await assert.rejects(
        crypto.decrypt('bob', 'alice', next, senderIdentity),
        /Replay or out-of-order/
    );
    assert.equal(crypto.loadSession('bob', 'alice').recvCounter, 2);
});

test('a failed first-message authentication does not persist an inbound session', async () => {
    const { envelope, senderIdentity } = await createInitialMessage('alice', 'bob');
    const altered = { ...envelope, ciphertext: `${envelope.ciphertext.slice(0, -4)}AAAA` };

    await assert.rejects(
        crypto.decrypt('bob', 'alice', altered, senderIdentity),
        /Authentication tag verification failed/
    );
    assert.equal(crypto.loadSession('bob', 'alice'), null);
});

test('tampering with iv or auth tag fails authenticated decryption and rejects message', async () => {
    const { envelope, senderIdentity } = await createInitialMessage('alice', 'bob');
    await crypto.decrypt('bob', 'alice', envelope, senderIdentity);

    // 1. IV tampering
    const tamperedIv = await crypto.encrypt('alice', 'bob', 'secret iv test', 'iv');
    await assert.rejects(
        crypto.decrypt('bob', 'alice', tamperedIv, senderIdentity),
        /Authentication tag verification failed/
    );

    // 2. Auth tag tampering
    const tamperedTag = await crypto.encrypt('alice', 'bob', 'secret tag test', 'tag');
    await assert.rejects(
        crypto.decrypt('bob', 'alice', tamperedTag, senderIdentity),
        /Authentication tag verification failed/
    );

    // 3. Subsequent authentic message succeeds because session state was not corrupted
    const validMsg = await crypto.encrypt('alice', 'bob', 'authentic after tamper attempts');
    const decrypted = await crypto.decrypt('bob', 'alice', validMsg, senderIdentity);
    assert.equal(decrypted, 'authentic after tamper attempts');
});

test('cryptographic utilities extract valid nonce hex, auth tag hex, and ciphertext hex', async () => {
    const { envelope } = await createInitialMessage('alice', 'bob');
    const nonceHex = crypto.extractNonceHex(envelope.iv);
    const authTagHex = crypto.extractAuthTagHex(envelope.ciphertext);
    const ctHex = crypto.extractCiphertextHex(envelope.ciphertext);

    // Nonce must be 12 bytes
    assert.equal(nonceHex.split(' ').length, 12);
    // AES-GCM tag must be 16 bytes (128 bits)
    assert.equal(authTagHex.split(' ').length, 16);
    // Ciphertext hex must be non-empty
    assert.ok(ctHex.length > 0);
});

function createClientEnvironment(username) {
    const storage = new Map();
    const windowStub = {
        crypto: webcrypto,
        btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
        atob: (value) => Buffer.from(value, 'base64').toString('binary')
    };

    const ctx = vm.createContext({
        window: windowStub,
        TextDecoder,
        TextEncoder,
        localStorage: {
            getItem: (key) => storage.get(key) ?? null,
            setItem: (key, value) => storage.set(key, String(value)),
            removeItem: (key) => storage.delete(key)
        },
        sessionStorage: {
            setItem: () => {},
            getItem: () => null,
            removeItem: () => {}
        }
    });

    vm.runInContext(
        fs.readFileSync(path.join(__dirname, '..', 'js', 'crypto.js'), 'utf8'),
        ctx,
        { filename: 'crypto.js' }
    );

    return {
        username,
        crypto: windowStub.e2eeCrypto,
        storage,
        context: ctx,
        window: windowStub
    };
}

test('key generation exports complete P-256 JWKs and rejects wrapped or incomplete JWK inputs', async () => {
    const client = createClientEnvironment('jwk-format');
    const keys = await client.crypto.getUserKeys('jwk-format');

    for (const jwk of [keys.ik_pub_jwk, keys.spk_pub_jwk, keys.signing_pub_jwk]) {
        assert.equal(jwk.kty, 'EC');
        assert.equal(jwk.crv, 'P-256');
        assert.equal(typeof jwk.x, 'string');
        assert.equal(typeof jwk.y, 'string');
        assert.equal('d' in jwk, false);
    }
    for (const jwk of [keys.ik_priv_jwk, keys.spk_priv_jwk, keys.signing_priv_jwk]) {
        assert.equal(jwk.kty, 'EC');
        assert.equal(jwk.crv, 'P-256');
        assert.equal(typeof jwk.x, 'string');
        assert.equal(typeof jwk.y, 'string');
        assert.equal(typeof jwk.d, 'string');
    }

    await assert.rejects(
        client.crypto.importPublicKeyJwk({ jwk: keys.ik_pub_jwk }),
        /Expected an EC P-256 public JWK containing kty, crv, x, and y/
    );
    await assert.rejects(
        client.crypto.importECDSAPrivateKeyJwk({ ...keys.signing_priv_jwk, kty: undefined }),
        /Expected an EC P-256 private JWK containing kty, crv, x, y, and d/
    );
});

test('signed-prekey generation signs with the ECDSA private CryptoKey and verifies with its public JWK', async () => {
    const client = createClientEnvironment('signed-prekey');
    const keys = await client.crypto.getUserKeys('signed-prekey');
    const bundle = await client.crypto.buildSignedPrekeyBundle('signed-prekey', keys);
    const signedPrekey = JSON.parse(bundle.signed_prekey_pubkey);
    const identity = JSON.parse(bundle.identity_pubkey);

    assert.equal(keys.signing_priv.type, 'private');
    assert.equal(keys.signing_priv.algorithm.name, 'ECDSA');
    assert.equal(keys.signing_priv.algorithm.namedCurve, 'P-256');
    assert.equal(
        (await client.crypto.verifySignedPrekey(
            identity,
            signedPrekey,
            bundle.signed_prekey_signature
        )).valid,
        true
    );
    await assert.rejects(
        client.crypto.signObjectWithPrivateKey(keys.signing_priv_jwk, signedPrekey),
        /Expected an ECDSA P-256 private CryptoKey with signing permission/
    );
});

test('registration submits exported public JWKs and a verifiable ECDSA signed prekey', async () => {
    const client = createClientEnvironment('register-flow');
    let requestBody;
    client.context.fetch = async (url, options) => {
        assert.equal(url, '/api/auth/register');
        requestBody = JSON.parse(options.body);
        return {
            ok: true,
            json: async () => ({
                access_token: 'test-token',
                username: 'register-flow'
            })
        };
    };

    vm.runInContext(
        fs.readFileSync(path.join(__dirname, '..', 'js', 'auth.js'), 'utf8'),
        client.context,
        { filename: 'auth.js' }
    );

    await client.window.Auth.register('register-flow', 'Password123!');
    const identity = JSON.parse(requestBody.identity_pubkey);
    const prekey = JSON.parse(requestBody.prekey_pubkey);
    const signedPrekey = JSON.parse(requestBody.signed_prekey_pubkey);

    assert.equal(identity.kty, 'EC');
    assert.equal(identity.crv, 'P-256');
    assert.equal(typeof identity.x, 'string');
    assert.equal(typeof identity.y, 'string');
    assert.equal(identity.signing_pubkey.kty, 'EC');
    assert.equal(prekey.kty, 'EC');
    assert.equal(signedPrekey.kty, 'EC');
    assert.equal(requestBody.signature_algorithm, 'ECDSA-P-256-SHA256');
    assert.equal(
        (await client.crypto.verifySignedPrekey(
            identity,
            signedPrekey,
            requestBody.signed_prekey_signature
        )).valid,
        true
    );
});

test('registration safely replaces an invalid saved JWK only after backend success', async () => {
    const client = createClientEnvironment('cached-key-repair');
    const storageKey = 'e2ee_keys_cached-key-repair';
    const invalidRecord = JSON.stringify({ signing_priv: { type: 'private' } });
    client.storage.set(storageKey, invalidRecord);
    client.context.fetch = async () => ({
        ok: false,
        json: async () => ({ detail: 'Username already registered.' })
    });

    vm.runInContext(
        fs.readFileSync(path.join(__dirname, '..', 'js', 'auth.js'), 'utf8'),
        client.context,
        { filename: 'auth.js' }
    );

    await assert.rejects(
        client.window.Auth.register('cached-key-repair', 'Password123!'),
        /Username already registered/
    );
    assert.equal(client.storage.get(storageKey), invalidRecord);

    let requestBody;
    client.context.fetch = async (url, options) => {
        requestBody = JSON.parse(options.body);
        return {
            ok: true,
            json: async () => ({
                access_token: 'test-token',
                username: 'cached-key-repair'
            })
        };
    };

    await client.window.Auth.register('cached-key-repair', 'Password123!');
    const repairedRecord = JSON.parse(client.storage.get(storageKey));
    assert.equal(repairedRecord.signing_priv.kty, 'EC');
    assert.equal(repairedRecord.signing_priv.crv, 'P-256');
    assert.equal(typeof repairedRecord.signing_priv.d, 'string');

    const identity = JSON.parse(requestBody.identity_pubkey);
    const signedPrekey = JSON.parse(requestBody.signed_prekey_pubkey);
    assert.equal(
        (await client.crypto.verifySignedPrekey(
            identity,
            signedPrekey,
            requestBody.signed_prekey_signature
        )).valid,
        true
    );
});

test('invalid signed prekey signatures are rejected by the live key-exchange path', async () => {
    const alice = createClientEnvironment('alice');
    const bob = createClientEnvironment('bob');
    const bobKeys = await bob.crypto.getUserKeys('bob');
    const bundle = await bob.crypto.buildSignedPrekeyBundle('bob');
    const tamperedPrekey = JSON.parse(bundle.signed_prekey_pubkey);
    tamperedPrekey.kid = 'tampered-spk';

    await assert.rejects(
        alice.crypto.initializeOutboundSession(
            'alice',
            'bob',
            bobKeys.ik_pub_jwk,
            bobKeys.spk_pub_jwk,
            tamperedPrekey,
            bundle.signed_prekey_signature
        ),
        /Identity verification for bob failed:/
    );
});

test('modified ciphertext is rejected by the actual authenticated-message path', async () => {
    const { envelope, senderIdentity } = await createInitialMessage('alice', 'bob');
    const modified = {
        ...envelope,
        ciphertext: `${envelope.ciphertext.slice(0, -2)}AA`
    };

    await assert.rejects(
        crypto.decrypt('bob', 'alice', modified, senderIdentity),
        /SECURITY ALERT: Authentication tag verification failed/
    );
});
