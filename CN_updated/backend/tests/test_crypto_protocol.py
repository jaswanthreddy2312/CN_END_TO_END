import os
import json
import base64
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
    load_pem_public_key,
    load_pem_private_key
)

# -------------------------------------------------------------
# Pure Cryptographic Primitives Implementation for Double Ratchet
# -------------------------------------------------------------

def generate_ecdh_keypair():
    """Generate an ECDH P-256 keypair."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    return priv, pub

def export_pubkey_b64(pub_key) -> str:
    """Export public key to base64 PEM."""
    pem = pub_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(pem).decode("utf-8")

def import_pubkey_b64(pub_b64: str):
    """Import public key from base64 PEM."""
    pem = base64.b64decode(pub_b64)
    return load_pem_public_key(pem)

def compute_ecdh(priv_key, remote_pub_key) -> bytes:
    """Compute raw ECDH shared secret (32 bytes)."""
    return priv_key.exchange(ec.ECDH(), remote_pub_key)

def hkdf_derive(secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive keys using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else b"\x00" * 32,
        info=info,
    )
    return hkdf.derive(secret)

def compute_safety_number(pub_a_b64: str, pub_b_b64: str) -> str:
    """
    Compute a fingerprint / safety number from two public keys.
    Order is normalized so both parties compute identical numbers.
    Returns 6 blocks of 5 digits (30 digits total).
    """
    digest_a = hashes.Hash(hashes.SHA256())
    digest_a.update(pub_a_b64.encode("utf-8"))
    hash_a = digest_a.finalize()

    digest_b = hashes.Hash(hashes.SHA256())
    digest_b.update(pub_b_b64.encode("utf-8"))
    hash_b = digest_b.finalize()

    # Sort lexicographically
    combined = hash_a + hash_b if hash_a < hash_b else hash_b + hash_a

    digest = hashes.Hash(hashes.SHA256())
    digest.update(combined)
    final_hash = digest.finalize()

    # Convert first 15 bytes into numbers
    blocks = []
    for i in range(0, 15, 2):
        val = int.from_bytes(final_hash[i:i+2], byteorder="big") % 100000
        blocks.append(f"{val:05d}")
    return " ".join(blocks[:6])

# -------------------------------------------------------------
# Double Ratchet Session Engine
# -------------------------------------------------------------

class RatchetSession:
    def __init__(self, username: str, is_initiator: bool):
        self.username = username
        self.is_initiator = is_initiator
        self.root_key = None
        self.sending_chain_key = None
        self.receiving_chain_key = None
        self.dh_pair = None # (priv, pub)
        self.remote_dh_pub = None
        self.send_counter = 0
        self.recv_counter = 0

    @classmethod
    def initiate(cls, sender: str, recipient_pub_identity, recipient_pub_prekey):
        """Initiate session using X3DH-style key agreement and setup root ratchet."""
        session = cls(sender, is_initiator=True)
        # Sender identity & ephemeral
        ik_priv, ik_pub = generate_ecdh_keypair()
        session.identity_pair = (ik_priv, ik_pub)
        ek_priv, ek_pub = generate_ecdh_keypair()

        # Ephemeral DH ratchet key
        dhk_priv, dhk_pub = generate_ecdh_keypair()
        session.dh_pair = (dhk_priv, dhk_pub)
        session.remote_dh_pub = recipient_pub_prekey

        # X3DH calculations:
        dh1 = compute_ecdh(ik_priv, recipient_pub_prekey)
        dh2 = compute_ecdh(ek_priv, recipient_pub_identity)
        dh3 = compute_ecdh(ek_priv, recipient_pub_prekey)
        dh_total = dh1 + dh2 + dh3

        # Derive initial master root key SK
        sk = hkdf_derive(dh_total, salt=b"E2EE_X3DH_SALT_V1", info=b"WhisperRatchetRootKey", length=32)
        session.root_key = sk

        # Perform initial DH Ratchet step to obtain sending chain key
        dh_ratchet = compute_ecdh(dhk_priv, recipient_pub_prekey)
        kdf_out = hkdf_derive(dh_ratchet, salt=session.root_key, info=b"WhisperRatchetStep", length=64)
        session.root_key = kdf_out[:32]
        session.sending_chain_key = kdf_out[32:]

        return session, ik_pub, ek_pub, dhk_pub

    @classmethod
    def receive_init(cls, recipient: str, ik_recipient_pair, spk_recipient_pair,
                     sender_ik_pub, sender_ek_pub, sender_dhk_pub):
        """Initialize recipient side from initial message."""
        session = cls(recipient, is_initiator=False)
        session.identity_pair = ik_recipient_pair
        session.dh_pair = spk_recipient_pair
        session.remote_dh_pub = sender_dhk_pub

        # X3DH calculations:
        dh1 = compute_ecdh(spk_recipient_pair[0], sender_ik_pub)
        dh2 = compute_ecdh(ik_recipient_pair[0], sender_ek_pub)
        dh3 = compute_ecdh(spk_recipient_pair[0], sender_ek_pub)
        dh_total = dh1 + dh2 + dh3

        # Derive SK
        sk = hkdf_derive(dh_total, salt=b"E2EE_X3DH_SALT_V1", info=b"WhisperRatchetRootKey", length=32)
        session.root_key = sk

        # Setup receiving chain key matching sender's DH ratchet step
        dh_ratchet = compute_ecdh(spk_recipient_pair[0], sender_dhk_pub)
        kdf_out = hkdf_derive(dh_ratchet, salt=session.root_key, info=b"WhisperRatchetStep", length=64)
        session.root_key = kdf_out[:32]
        session.receiving_chain_key = kdf_out[32:]

        return session

    def encrypt_message(self, plaintext: str) -> dict:
        """Encrypt message using fresh symmetric ratchet message key."""
        if not self.sending_chain_key:
            # Need to create new sending chain via DH ratchet step
            new_dh_priv, new_dh_pub = generate_ecdh_keypair()
            dh_secret = compute_ecdh(new_dh_priv, self.remote_dh_pub)
            kdf_out = hkdf_derive(dh_secret, salt=self.root_key, info=b"WhisperRatchetStep", length=64)
            self.root_key = kdf_out[:32]
            self.sending_chain_key = kdf_out[32:]
            self.dh_pair = (new_dh_priv, new_dh_pub)
            self.send_counter = 0

        # Derive message key from current sending chain key
        mk = hkdf_derive(self.sending_chain_key, salt=b"", info=b"MessageKey", length=32)
        # Advance the symmetric chain key.
        self.sending_chain_key = hkdf_derive(self.sending_chain_key, salt=b"", info=b"ChainAdvance", length=32)

        # Encrypt with AES-256-GCM
        iv = os.urandom(12)
        aesgcm = AESGCM(mk)
        ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), associated_data=None)

        msg_num = self.send_counter
        self.send_counter += 1

        # Delete message key from memory (simulated)
        del mk

        return {
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8"),
            "dh_ratchet_pubkey": export_pubkey_b64(self.dh_pair[1]),
            "msg_counter": msg_num
        }

    def decrypt_message(self, env: dict) -> str:
        """Decrypt message and step ratchet if remote DH key changed."""
        remote_dh_b64 = env["dh_ratchet_pubkey"]
        remote_dh_key = import_pubkey_b64(remote_dh_b64)

        # Check if remote DH key has changed -> perform DH ratchet step
        current_remote_b64 = export_pubkey_b64(self.remote_dh_pub) if self.remote_dh_pub else None
        if remote_dh_b64 != current_remote_b64:
            self.remote_dh_pub = remote_dh_key
            dh_secret = compute_ecdh(self.dh_pair[0], remote_dh_key)
            kdf_out = hkdf_derive(dh_secret, salt=self.root_key, info=b"WhisperRatchetStep", length=64)
            self.root_key = kdf_out[:32]
            self.receiving_chain_key = kdf_out[32:]
            self.recv_counter = 0

        # Derive message key from receiving chain key
        mk = hkdf_derive(self.receiving_chain_key, salt=b"", info=b"MessageKey", length=32)
        # Advance receiving chain key
        self.receiving_chain_key = hkdf_derive(self.receiving_chain_key, salt=b"", info=b"ChainAdvance", length=32)

        # AES-256-GCM decryption
        iv = base64.b64decode(env["iv"])
        ciphertext = base64.b64decode(env["ciphertext"])
        aesgcm = AESGCM(mk)
        plaintext_bytes = aesgcm.decrypt(iv, ciphertext, associated_data=None)

        self.recv_counter += 1
        del mk

        return plaintext_bytes.decode("utf-8")

# -------------------------------------------------------------
# Unit & Security Tests
# -------------------------------------------------------------

def test_full_e2ee_key_exchange_and_message():
    """Verify complete key exchange, encryption, and decryption flow."""
    # 1. User B registers keys
    b_ik_priv, b_ik_pub = generate_ecdh_keypair()
    b_spk_priv, b_spk_pub = generate_ecdh_keypair()

    # 2. User A initiates conversation
    alice_session, a_ik_pub, a_ek_pub, a_dhk_pub = RatchetSession.initiate(
        "Alice", b_ik_pub, b_spk_pub
    )

    # 3. User B receives initial handshake
    bob_session = RatchetSession.receive_init(
        "Bob",
        (b_ik_priv, b_ik_pub),
        (b_spk_priv, b_spk_pub),
        a_ik_pub,
        a_ek_pub,
        a_dhk_pub
    )

    # 4. Alice sends message to Bob
    secret_text = "Hello Bob! This message is protected by E2EE and Double Ratchet."
    payload = alice_session.encrypt_message(secret_text)

    # 5. Bob decrypts message
    decrypted = bob_session.decrypt_message(payload)
    assert decrypted == secret_text

    # 6. Bob replies to Alice
    reply_text = "Hey Alice! I verified the message tag and advanced my ratchet."
    reply_payload = bob_session.encrypt_message(reply_text)
    decrypted_reply = alice_session.decrypt_message(reply_payload)
    assert decrypted_reply == reply_text

def test_ciphertext_tampering_rejection():
    """Verify that any modification of ciphertext causes authentication failure."""
    b_ik_priv, b_ik_pub = generate_ecdh_keypair()
    b_spk_priv, b_spk_pub = generate_ecdh_keypair()

    alice_session, a_ik_pub, a_ek_pub, a_dhk_pub = RatchetSession.initiate(
        "Alice", b_ik_pub, b_spk_pub
    )
    bob_session = RatchetSession.receive_init(
        "Bob", (b_ik_priv, b_ik_pub), (b_spk_priv, b_spk_pub),
        a_ik_pub, a_ek_pub, a_dhk_pub
    )

    payload = alice_session.encrypt_message("Authentic confidential message")
    
    # Tamper with the ciphertext (flip a byte)
    raw_ct = bytearray(base64.b64decode(payload["ciphertext"]))
    raw_ct[0] ^= 0xFF  # Corrupt 1 byte
    payload["ciphertext"] = base64.b64encode(raw_ct).decode("utf-8")

    # Bob must REJECT the tampered ciphertext with an error
    with pytest.raises(Exception):
        bob_session.decrypt_message(payload)

def test_iv_tampering_rejection():
    """Verify that tampering with IV causes authentication tag verification failure."""
    b_ik_priv, b_ik_pub = generate_ecdh_keypair()
    b_spk_priv, b_spk_pub = generate_ecdh_keypair()

    alice_session, a_ik_pub, a_ek_pub, a_dhk_pub = RatchetSession.initiate(
        "Alice", b_ik_pub, b_spk_pub
    )
    bob_session = RatchetSession.receive_init(
        "Bob", (b_ik_priv, b_ik_pub), (b_spk_priv, b_spk_pub),
        a_ik_pub, a_ek_pub, a_dhk_pub
    )

    payload = alice_session.encrypt_message("Another authentic message")
    
    # Tamper with IV
    raw_iv = bytearray(base64.b64decode(payload["iv"]))
    raw_iv[0] ^= 0x01
    payload["iv"] = base64.b64encode(raw_iv).decode("utf-8")

    with pytest.raises(Exception):
        bob_session.decrypt_message(payload)

def test_chain_kdf_evolves_to_distinct_keys():
    """Check that successive KDF inputs produce distinct keys, not full forward secrecy."""
    ck0 = os.urandom(32)
    # Derive message key 0 and advance to chain key 1
    mk0 = hkdf_derive(ck0, salt=b"", info=b"MessageKey", length=32)
    ck1 = hkdf_derive(ck0, salt=b"", info=b"ChainAdvance", length=32)

    # Derive message key 1 and advance to chain key 2
    mk1 = hkdf_derive(ck1, salt=b"", info=b"MessageKey", length=32)
    ck2 = hkdf_derive(ck1, salt=b"", info=b"ChainAdvance", length=32)

    assert mk0 != mk1
    assert ck0 != ck1 != ck2
    # This checks distinct outputs only; it is not a formal forward-secrecy proof.

def test_safety_number_symmetry():
    """Verify that safety numbers computed by Alice and Bob are strictly identical."""
    _, a_pub = generate_ecdh_keypair()
    _, b_pub = generate_ecdh_keypair()

    a_b64 = export_pubkey_b64(a_pub)
    b_b64 = export_pubkey_b64(b_pub)

    # Alice computes safety number (her key, then Bob's key)
    sn_alice = compute_safety_number(a_b64, b_b64)
    # Bob computes safety number (his key, then Alice's key)
    sn_bob = compute_safety_number(b_b64, a_b64)

    assert sn_alice == sn_bob
    assert len(sn_alice.replace(" ", "")) == 30
