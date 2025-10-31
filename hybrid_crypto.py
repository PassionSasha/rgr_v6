from __future__ import annotations
import os
import json
import base64
from dataclasses import dataclass
from typing import Optional, Literal, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives import hashes, serialization, constant_time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Вимоги варіанту №6
NONCE_LEN = 13          # AES-CCM nonce
AES_KEY_LEN = 16        # 128 біт
TAG_LEN = 16            # 128 біт тег AEAD

KDFType = Literal["random", "pbkdf2"]

@dataclass
class KDFParams:
    method: KDFType
    salt: Optional[bytes] = None
    iterations: Optional[int] = None
    passphrase: Optional[bytes] = None

def derive_session_key(params: KDFParams) -> Tuple[bytes, dict]:
    if params.method == "random":
        key = os.urandom(AES_KEY_LEN)
        return key, {"method": "random"}
    elif params.method == "pbkdf2":
        if not params.passphrase:
            raise ValueError("PBKDF2 requires passphrase")
        salt = params.salt or os.urandom(16)
        iterations = params.iterations or 300_000
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_LEN,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        key = kdf.derive(params.passphrase)
        return key, {
            "method": "pbkdf2",
            "salt": salt.hex(),
            "iterations": iterations,
            "hash": "SHA256",
        }
    else:
        raise ValueError("Unsupported KDF method")

def load_public_key(pem_path: str):
    with open(pem_path, "rb") as f:
        data = f.read()
    return serialization.load_pem_public_key(data, backend=default_backend())

def load_private_key(pem_path: str, password: Optional[bytes] = None):
    with open(pem_path, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=password, backend=default_backend())

def rsa_oaep_encrypt(pubkey, plaintext: bytes) -> bytes:
    return pubkey.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_oaep_decrypt(privkey, ciphertext: bytes) -> bytes:
    return privkey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def aes_ccm_encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_LEN)
    aead = AESCCM(key, tag_length=TAG_LEN)
    ciphertext = aead.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext

def aes_ccm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
    aead = AESCCM(key, tag_length=TAG_LEN)
    return aead.decrypt(nonce, ciphertext, aad)

def hybrid_encrypt(
    plaintext: bytes,
    pubkey_pem: str,
    kdf_params: KDFParams,
    aad: Optional[bytes] = None,
) -> bytes:
    session_key, kdf_meta = derive_session_key(kdf_params)
    nonce, ct = aes_ccm_encrypt(session_key, plaintext, aad=aad)

    pub = load_public_key(pubkey_pem)
    ekey = rsa_oaep_encrypt(pub, session_key)

    asym_bits = getattr(pub, "key_size", 2048)
    header = {
        "format": "RGR6-AESCCM-RSAOAEP",
        "sym": {"alg": "AES-CCM", "key_bits": 128, "tag_bits": TAG_LEN * 8, "nonce_len": NONCE_LEN},
        "asym": {"alg": "RSA-OAEP", "key_bits": asym_bits, "hash": "SHA256"},
        "kdf": kdf_meta,
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ekey_b64": base64.b64encode(ekey).decode("ascii"),
    }
    if aad:
        header["aad_b64"] = base64.b64encode(aad).decode("ascii")

    header_bytes = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return header_bytes + b"\n\n" + ct

def hybrid_decrypt(
    container: bytes,
    privkey_pem: str,
    passphrase_for_pbkdf2: Optional[bytes] = None,
) -> bytes:
    try:
        header_bytes, payload = container.split(b"\n\n", 1)
    except ValueError:
        raise ValueError("Invalid container format: header/payload separator not found")

    header = json.loads(header_bytes.decode("utf-8"))
    nonce = base64.b64decode(header["nonce_b64"])
    ekey = base64.b64decode(header["ekey_b64"])
    aad = base64.b64decode(header["aad_b64"]) if "aad_b64" in header else None

    priv = load_private_key(privkey_pem, password=None)
    session_key = rsa_oaep_decrypt(priv, ekey)

    if header.get("kdf", {}).get("method") == "pbkdf2":
        if passphrase_for_pbkdf2 is None:
            raise ValueError("Passphrase is required for PBKDF2-derived key validation")
        salt_hex = header["kdf"]["salt"]
        iterations = int(header["kdf"]["iterations"])
        salt = bytes.fromhex(salt_hex)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=len(session_key),
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        ref_key = kdf.derive(passphrase_for_pbkdf2)
        if not constant_time.bytes_eq(ref_key, session_key):
            raise ValueError("PBKDF2 key mismatch (wrong passphrase?)")

    plaintext = aes_ccm_decrypt(session_key, nonce, payload, aad=aad)
    return plaintext
