import base64
import binascii
import json
import re
from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Optional

class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, description="Alphanumeric username")
    password: str = Field(..., min_length=8, max_length=128, description="User password")
    identity_pubkey: str = Field(..., min_length=10, description="Client ECDH identity public key")
    prekey_pubkey: str = Field(..., min_length=10, description="Client ECDH prekey public key")
    signed_prekey_pubkey: Optional[str] = Field(default=None, min_length=10, description="Signed prekey public key bundle")
    signed_prekey_signature: Optional[str] = Field(default=None, min_length=10, description="ECDSA signature over the signed prekey")
    signature_algorithm: Optional[str] = Field(default='ECDSA-P-256-SHA256', max_length=64)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        clean = v.strip()
        if not re.match(r"^[a-zA-Z0-9_-]+$", clean):
            raise ValueError("Username can only contain alphanumeric characters, underscores, and hyphens.")
        return clean

class UserLoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str

class UserProfile(BaseModel):
    id: int
    username: str
    identity_pubkey: str
    prekey_pubkey: str
    signed_prekey_pubkey: Optional[str] = None
    signed_prekey_signature: Optional[str] = None
    signature_algorithm: Optional[str] = None
    is_online: bool = False
    last_seen: Optional[str] = None

class KeyBundleResponse(BaseModel):
    username: str
    identity_pubkey: str
    prekey_pubkey: str
    signed_prekey_pubkey: Optional[str] = None
    signed_prekey_signature: Optional[str] = None
    signature_algorithm: Optional[str] = None

class PrekeyUpdateRequest(BaseModel):
    prekey_pubkey: str
    signed_prekey_pubkey: Optional[str] = None
    signed_prekey_signature: Optional[str] = None
    signature_algorithm: Optional[str] = 'ECDSA-P-256-SHA256'

class EncryptedMessageEnvelope(BaseModel):
    """
    Opaque container for client-to-client encrypted messages.
    Notice: NO plaintext fields exist here!
    """
    model_config = ConfigDict(extra="forbid")

    message_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    sender: Optional[str] = Field(default=None, max_length=30)
    recipient: str = Field(min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_-]+$")
    ciphertext: str = Field(min_length=24, max_length=1_400_000)
    iv: str = Field(min_length=16, max_length=16)
    dh_ratchet_pubkey: str = Field(min_length=1, max_length=2048)
    msg_counter: int = Field(ge=0, le=2_147_483_647)
    prev_chain_len: int = Field(default=0, ge=0, le=2_147_483_647)
    timestamp: int = Field(ge=0, le=9_007_199_254_740_991)
    is_initial: bool = False
    ephemeral_pubkey: Optional[str] = Field(default=None, max_length=2048)

    @field_validator("ciphertext", "iv")
    @classmethod
    def validate_base64(cls, value: str, info):
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Encrypted message fields must use standard base64.") from exc
        if info.field_name == "iv" and len(decoded) != 12:
            raise ValueError("AES-GCM nonces must be 12 bytes.")
        if info.field_name == "ciphertext" and len(decoded) < 16:
            raise ValueError("Ciphertext must include an authentication tag.")
        return value

    @field_validator("dh_ratchet_pubkey", "ephemeral_pubkey")
    @classmethod
    def validate_public_jwk(cls, value: Optional[str]):
        if value is None:
            return value
        try:
            jwk = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("Ratchet keys must be JSON-encoded public JWKs.") from exc
        if (
            not isinstance(jwk, dict)
            or jwk.get("kty") != "EC"
            or jwk.get("crv") != "P-256"
            or "d" in jwk
            or not isinstance(jwk.get("x"), str)
            or not isinstance(jwk.get("y"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", jwk["x"])
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", jwk["y"])
        ):
            raise ValueError("Ratchet keys must contain only a P-256 public key.")
        return value
