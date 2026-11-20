"""
Enterprise Cryptographic Vault Security for Prometheus.
Provides AES-256-GCM symmetric encryption for tenant integration secrets, API tokens, and PATs at rest in Firestore.
"""

import os
import base64
import hashlib
import logging
import secrets
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("prometheus.security.vault_crypto")


def _resolve_vault_seed() -> str:
    env_key = os.getenv("VAULT_MASTER_KEY") or os.getenv("SECRET_KEY")
    if env_key:
        return env_key
    if os.getenv("ENVIRONMENT", "").lower() == "production":
        raise RuntimeError("FATAL: VAULT_MASTER_KEY must be configured in production.")
    return secrets.token_hex(32)


def _resolve_vault_salt() -> bytes:
    env_salt = os.getenv("VAULT_KDF_SALT")
    if env_salt:
        return env_salt.encode("utf-8")
    if os.getenv("ENVIRONMENT", "").lower() == "production":
        raise RuntimeError("FATAL: VAULT_KDF_SALT must be configured in production.")
    return secrets.token_bytes(16)


DEFAULT_VAULT_SEED = _resolve_vault_seed()
DEFAULT_VAULT_SALT = _resolve_vault_salt()


class VaultCrypto:
    """
    AES-256-GCM symmetric cipher utility for securing third-party credentials.
    """

    def __init__(self, master_key: Optional[str] = None):
        seed = (master_key or DEFAULT_VAULT_SEED).encode("utf-8")
        salt = os.getenv("VAULT_KDF_SALT").encode("utf-8") if os.getenv("VAULT_KDF_SALT") else DEFAULT_VAULT_SALT
        self._key = hashlib.pbkdf2_hmac("sha256", seed, salt, 100_000, dklen=32)
        self._aesgcm = AESGCM(self._key)

    def encrypt(self, plaintext: str, associated_data: Optional[bytes] = None) -> str:
        """
        Encrypts plaintext string with fresh 96-bit nonce and returns URL-safe Base64 ciphertext.
        Format: nonce (12 bytes) + ciphertext + auth_tag (16 bytes)
        """
        if not plaintext:
            return ""
        try:
            nonce = os.urandom(12)
            ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
            combined = nonce + ciphertext
            return "enc:v1:" + base64.urlsafe_b64encode(combined).decode("ascii")
        except Exception as e:
            logger.error(f"Failed to encrypt secret payload: {e}")
            raise

    def decrypt(self, encoded_ciphertext: str, associated_data: Optional[bytes] = None) -> str:
        """
        Decrypts an encrypted string. Returns empty string on decryption failure to prevent leaking raw ciphertext.
        """
        if not encoded_ciphertext:
            return ""
        if not encoded_ciphertext.startswith("enc:v1:"):
            return encoded_ciphertext
        try:
            raw_b64 = encoded_ciphertext[7:]
            combined = base64.urlsafe_b64decode(raw_b64.encode("ascii"))
            nonce = combined[:12]
            ciphertext = combined[12:]
            decrypted = self._aesgcm.decrypt(nonce, ciphertext, associated_data)
            return decrypted.decode("utf-8")
        except Exception as e:
            logger.warning(f"Failed to decrypt vault secret (possible key mismatch or corrupted data): {e}")
            return ""

    @staticmethod
    def mask_token(token: str, prefix_len: int = 4, suffix_len: int = 4) -> str:
        """
        Generates a secure display mask for API tokens (e.g. ghp_••••••••••••3a9f).
        """
        if not token:
            return ""
        # If token is encrypted string, don't display raw cipher
        if token.startswith("enc:v1:"):
            return "••••••••••••••••"
        if len(token) <= (prefix_len + suffix_len):
            return "••••••••"
        prefix = token[:prefix_len]
        suffix = token[-suffix_len:]
        return f"{prefix}••••••••{suffix}"


vault_crypto = VaultCrypto()

