from __future__ import annotations
import os, json, base64, uuid, pathlib
from dataclasses import dataclass
from typing import Optional, Literal, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives import hashes, serialization, constant_time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding

# Параметри варіанту №6
NONCE_LEN = 13          # AES-CCM nonce (L=2 → 13 байт)
AES_KEY_LEN = 16        # 128 біт
TAG_LEN = 16            # 128 біт

KDFMethod = Literal["random", "pbkdf2"]

@dataclass
class KDFParams:
    method: KDFMethod
    passphrase: Optional[bytes] = None
    salt: Optional[bytes] = None
    iterations: Optional[int] = None

def _derive_session_key(kdf: KDFParams) -> Tuple[bytes, dict]:
    if kdf.method == "random":
        key = os.urandom(AES_KEY_LEN)
        return key, {"method": "random"}
    elif kdf.method == "pbkdf2":
        if not kdf.passphrase:
            raise ValueError("PBKDF2 requires passphrase")
        salt = kdf.salt or os.urandom(16)
        iters = kdf.iterations or 300_000
        d = PBKDF2HMAC(algorithm=hashes.SHA256(), length=AES_KEY_LEN, salt=salt, iterations=iters)
        key = d.derive(kdf.passphrase)
        return key, {
            "method": "pbkdf2",
            "hash": "SHA256",
            "iterations": iters,
            "salt": salt.hex()
        }
    else:
        raise ValueError("Unsupported KDF method")

def _load_pub(pem_path: str):
    data = pathlib.Path(pem_path).read_bytes()
    return serialization.load_pem_public_key(data)

def _load_priv(pem_path: str, password: Optional[bytes] = None):
    data = pathlib.Path(pem_path).read_bytes()
    return serialization.load_pem_private_key(data, password=password)

def _rsa_oaep_encrypt(pub, pt: bytes) -> bytes:
    return pub.encrypt(
        pt,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def _rsa_oaep_decrypt(priv, ct: bytes) -> bytes:
    return priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

class SecureStoreV6:
    """
    Сховище: кожен запис у підпапці <id>/ з файлами:
      - header.json  (метадані контейнера, ekey, nonce, kdf, тощо)
      - payload.bin  (ciphertext AES-CCM: тег усередині, за API)
    """
    def __init__(self, root: str):
        self.root = pathlib.Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(
        self,
        in_bytes: bytes,
        pubkey_pem: str,
        kdf: KDFParams = KDFParams(method="random"),
        aad: Optional[bytes] = None,
        user_meta: Optional[dict] = None,
    ) -> str:
        # 1) Сеансовий ключ
        session_key, kdf_meta = _derive_session_key(kdf)

        # 2) AES-CCM шифрування
        nonce = os.urandom(NONCE_LEN)
        aead = AESCCM(session_key, tag_length=TAG_LEN)
        ciphertext = aead.encrypt(nonce, in_bytes, aad)

        # 3) Обгортка ключа RSA-OAEP
        pub = _load_pub(pubkey_pem)
        ekey = _rsa_oaep_encrypt(pub, session_key)
        asym_bits = getattr(pub, "key_size", 2048)

        # 4) Заголовок
        header = {
            "format": "RGR6-STORE-V1",
            "sym": {"alg": "AES-CCM", "key_bits": AES_KEY_LEN * 8, "tag_bits": TAG_LEN * 8, "nonce_len": NONCE_LEN},
            "asym": {"alg": "RSA-OAEP", "key_bits": asym_bits, "hash": "SHA256"},
            "kdf": kdf_meta,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ekey_b64": base64.b64encode(ekey).decode("ascii"),
        }
        if aad is not None:
            header["aad_b64"] = base64.b64encode(aad).decode("ascii")
        if user_meta:
            header["meta"] = user_meta

        # 5) Збереження
        rid = str(uuid.uuid4())
        rec_dir = self.root / rid
        rec_dir.mkdir(parents=True, exist_ok=True)
        (rec_dir / "header.json").write_text(json.dumps(header, ensure_ascii=False, indent=2), "utf-8")
        (rec_dir / "payload.bin").write_bytes(ciphertext)
        return rid

    def get(
        self,
        record_id: str,
        privkey_pem: str,
        passphrase_for_pbkdf2: Optional[bytes] = None,
    ) -> tuple[bytes, dict]:
        rec_dir = self.root / record_id
        header = json.loads((rec_dir / "header.json").read_text("utf-8"))
        payload = (rec_dir / "payload.bin").read_bytes()

        nonce = base64.b64decode(header["nonce_b64"])
        ekey = base64.b64decode(header["ekey_b64"])
        aad = base64.b64decode(header["aad_b64"]) if "aad_b64" in header else None

        priv = _load_priv(privkey_pem, password=None)
        session_key = _rsa_oaep_decrypt(priv, ekey)

        # Перевірка PBKDF2-відтворюваності (якщо застосовано)
        kdf_meta = header.get("kdf", {})
        if kdf_meta.get("method") == "pbkdf2":
            if passphrase_for_pbkdf2 is None:
                raise ValueError("Passphrase required for PBKDF2 container")
            salt = bytes.fromhex(kdf_meta["salt"])
            iters = int(kdf_meta["iterations"])
            d = PBKDF2HMAC(algorithm=hashes.SHA256(), length=len(session_key), salt=salt, iterations=iters)
            ref = d.derive(passphrase_for_pbkdf2)
            if not constant_time.bytes_eq(ref, session_key):
                raise ValueError("PBKDF2 key mismatch (wrong passphrase?)")

        aead = AESCCM(session_key, tag_length=TAG_LEN)
        plaintext = aead.decrypt(nonce, payload, aad)
        return plaintext, header
