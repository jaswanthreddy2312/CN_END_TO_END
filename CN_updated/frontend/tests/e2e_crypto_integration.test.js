const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const { TextDecoder, TextEncoder } = require('node:util');

/**
 * End-to-End Cryptographic Protocol & Modules Test Suite
 * Tests:
 * 1. User Authentication Key Bundles (ECDH P-256 Identity & Prekey Pairs)
 * 2. End-to-End Encryption (Sender Browser -> AES-256-GCM -> Recipient Browser)
 * 3. Forward Secrecy & Message Key Rotation (Double Ratchet step & key erasure)
 * 4. Message Authentication & Integrity (AES-GCM 128-bit Tag validation)
 * 5. Real-Time Relay Envelope (Payload contains zero plaintext)
 * 6. Cryptographic Visualization Metrics (Plaintext, Ciphertext, Nonce Hex, Tag Hex)
 * 7. Tamper Detection & Rejection (Bit flipping detected, decryption rejected)
 */

function createClientEnvironment(username) {
    const storage = new Map();
    const windowStub = {
        crypto: webcrypto,
        btoa: (val) => Buffer.from(val, 'binary').toString('base64'),
        atob: (val) => Buffer.from(val, 'base64').toString('binary')
    };

    const ctx = vm.createContext({
        window: windowStub,
        TextDecoder,
        TextEncoder,
        localStorage: {
            getItem: (k) => storage.get(k) ?? null,
            setItem: (k, v) => storage.set(k, String(v)),
            removeItem: (k) => storage.delete(k)
        }
    });

    const cryptoScript = fs.readFileSync(path.join(__dirname, '..', 'js', 'crypto.js'), 'utf8');
    vm.runInContext(cryptoScript, ctx, { filename: 'crypto.js' });

    return {
        username,
        crypto: windowStub.e2eeCrypto,
        storage
    };
}

test('Full E2EE Lifecycle: Key Agreement, Forward Secrecy Ratchet, Auth Verification & Tamper Detection', async () => {
    // 1. Setup Alice and Bob client environments
    const alice = createClientEnvironment('alice');
    const bob = createClientEnvironment('bob');

    // 2. Client-Side Key Pair Generation (Module 1 & 2)
    const aliceKeys = await alice.crypto.getUserKeys('alice');
    const bobKeys = await bob.crypto.getUserKeys('bob');

    assert.ok(aliceKeys.ik_pub_jwk.x && aliceKeys.ik_pub_jwk.y, 'Alice generated P-256 Identity Key');
    assert.ok(bobKeys.spk_pub_jwk.x && bobKeys.spk_pub_jwk.y, 'Bob generated P-256 Prekey');

    // 3. Alice initiates outbound session to Bob (X3DH Key Agreement)
    const initResult = await alice.crypto.initializeOutboundSession(
        'alice',
        'bob',
        bobKeys.ik_pub_jwk,
        bobKeys.spk_pub_jwk
    );
    assert.ok(initResult.session.rootKey, 'Alice derived initial Root Key');

    // 4. Alice Encrypts First Message (Module 2 & 6)
    const plaintext1 = 'Hello Bob! This is our first confidential message.';
    const env1 = await alice.crypto.encrypt('alice', 'bob', plaintext1);
    env1.is_initial = true;
    env1.ephemeral_pubkey = initResult.handshake.ephemeral_pubkey;

    // Verify envelope has NO plaintext (Module 5)
    const wireStr1 = JSON.stringify(env1);
    assert.equal(wireStr1.includes(plaintext1), false, 'Wire payload contains zero plaintext');

    // Verify cryptographic metadata extraction (Module 6)
    const nonceHex1 = alice.crypto.extractNonceHex(env1.iv);
    const authTagHex1 = alice.crypto.extractAuthTagHex(env1.ciphertext);
    const ctHex1 = alice.crypto.extractCiphertextHex(env1.ciphertext);

    assert.equal(nonceHex1.split(' ').length, 12, 'Valid 12-byte nonce hex extracted');
    assert.equal(authTagHex1.split(' ').length, 16, 'Valid 16-byte AES-GCM auth tag hex extracted');
    assert.ok(ctHex1.length > 0, 'Valid ciphertext hex extracted');

    // 5. Bob receives and decrypts initial message (Module 2, 4, 6)
    const decrypted1 = await bob.crypto.decrypt('bob', 'alice', env1, aliceKeys.ik_pub_jwk);
    assert.equal(decrypted1, plaintext1, 'Bob decrypted and recovered original plaintext');

    // 6. Forward Secrecy: Alice sends Message 2 before Bob replies (Symmetric Ratchet advancement)
    const plaintext2 = 'Second message from Alice, advancing symmetric KDF chain.';
    const env2 = await alice.crypto.encrypt('alice', 'bob', plaintext2);

    assert.equal(env2.msg_counter, 1, 'Message counter incremented to 1');
    const decrypted2 = await bob.crypto.decrypt('bob', 'alice', env2, aliceKeys.ik_pub_jwk);
    assert.equal(decrypted2, plaintext2, 'Bob decrypted sequential in-order message');

    // Verify replay protection (Module 4)
    await assert.rejects(
        bob.crypto.decrypt('bob', 'alice', env2, aliceKeys.ik_pub_jwk),
        /Replay or out-of-order/,
        'Bob rejected duplicate/replayed message envelope'
    );

    // 7. Conversational Turn: Bob replies to Alice (Asymmetric DH Ratchet step)
    const replyText = 'Hey Alice! I received your encrypted messages and stepped my DH ratchet.';
    const replyEnv = await bob.crypto.encrypt('bob', 'alice', replyText);
    const decryptedReply = await alice.crypto.decrypt('alice', 'bob', replyEnv, bobKeys.ik_pub_jwk);
    assert.equal(decryptedReply, replyText, 'Alice decrypted Bob reply with updated DH ratchet');

    // 8. Tamper Detection Module (Module 4 & 7): Ciphertext Corruption
    const tamperedCtEnv = await alice.crypto.encrypt('alice', 'bob', 'Secret message that will be corrupted', 'ciphertext');
    await assert.rejects(
        bob.crypto.decrypt('bob', 'alice', tamperedCtEnv, aliceKeys.ik_pub_jwk),
        /Authentication tag verification failed/,
        'Bob rejected tampered ciphertext with cryptographic authentication failure'
    );

    // 9. Tamper Detection Module: Nonce / IV Corruption
    const tamperedIvEnv = await alice.crypto.encrypt('alice', 'bob', 'Secret with bad IV', 'iv');
    await assert.rejects(
        bob.crypto.decrypt('bob', 'alice', tamperedIvEnv, aliceKeys.ik_pub_jwk),
        /Authentication tag verification failed/,
        'Bob rejected envelope with tampered IV/nonce'
    );

    // 10. Tamper Detection Module: Authentication Tag Corruption
    const tamperedTagEnv = await alice.crypto.encrypt('alice', 'bob', 'Secret with bad Tag', 'tag');
    await assert.rejects(
        bob.crypto.decrypt('bob', 'alice', tamperedTagEnv, aliceKeys.ik_pub_jwk),
        /Authentication tag verification failed/,
        'Bob rejected envelope with altered authentication tag'
    );

    // 11. Ratchet Resilience: Subsequent legitimate message succeeds without desync
    const postTamperMsg = 'Legitimate message sent after tamper demonstrations.';
    const postTamperEnv = await alice.crypto.encrypt('alice', 'bob', postTamperMsg);
    const postTamperDecrypted = await bob.crypto.decrypt('bob', 'alice', postTamperEnv, aliceKeys.ik_pub_jwk);
    assert.equal(postTamperDecrypted, postTamperMsg, 'Session remained synchronized and functional after attacks');
});

