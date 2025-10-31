from __future__ import annotations
import pathlib
from typing import Optional, Literal

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    PKCS7SignatureBuilder,
    PKCS7Options
)

SigAlg = Literal["rsa-pss", "ecdsa-p256"]


# ---------------------------
# Завантаження ключів/сертифікатів
# ---------------------------
def load_priv_pem(path: str, password: Optional[bytes] = None):
    data = pathlib.Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=password)

def load_pub_pem(path: str):
    data = pathlib.Path(path).read_bytes()
    return serialization.load_pem_public_key(data)

def load_cert_pem(path: str):
    from cryptography import x509
    data = pathlib.Path(path).read_bytes()
    return x509.load_pem_x509_certificate(data)

def load_pkcs12(pfx_path: str, password: Optional[bytes]):
    from cryptography.hazmat.primitives.serialization import pkcs12
    data = pathlib.Path(pfx_path).read_bytes()
    return pkcs12.load_key_and_certificates(data, password=password)  # (priv, cert, chain)


def sign_detached_raw(data: bytes, priv_pem: str, alg: SigAlg, password: Optional[bytes] = None) -> bytes:
    priv = load_priv_pem(priv_pem, password=password)
    if alg == "rsa-pss":
        return priv.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    elif alg == "ecdsa-p256":
        return priv.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("Unsupported alg")

def verify_detached_raw(data: bytes, sig: bytes, pub_pem: str, alg: SigAlg) -> bool:
    pub = load_pub_pem(pub_pem)
    try:
        if alg == "rsa-pss":
            pub.verify(sig, data,
                       padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                       hashes.SHA256())
        else:
            pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ---------------------------
# PKCS#7 (CMS) DETACHED підпис (з сертифікатом)
# ---------------------------
def sign_pkcs7_detached(data: bytes, priv_pem: str, cert_pem: str,
                        password: Optional[bytes] = None,
                        include_certs: bool = True) -> bytes:
    """Повертає DER-encoded PKCS#7 (CMS) detached signature."""
    priv = load_priv_pem(priv_pem, password=password)
    cert = load_cert_pem(cert_pem)
    # За потреби можна додати chain (необов'язково)
    builder = PKCS7SignatureBuilder().set_data(data).add_signer(cert, priv, hashes.SHA256())
    opts = [PKCS7Options.DetachedSignature]
    if include_certs:
        # За замовчуванням cert додається; опція контролює поведінку деяких версій
        pass
    return builder.sign(serialization.Encoding.DER, options=opts)

def verify_pkcs7_detached(data: bytes, sig_der: bytes) -> bool:
    """Перевірка PKCS#7 (CMS) з використанням cert з контейнера.
       Ланцюжок/довіра CA тут НЕ перевіряються (це можна додати окремо)."""
    try:
        # cryptography (на момент підготовки) не дає прямої high-level валідації CMS,
        # але DER можна перевіряти через OpenSSL (якщо є у системі) або вручну парсити.
        # Для простоти: спробуємо через OpenSSL CLI (якщо є).
        import shutil, subprocess, tempfile, os
        openssl = shutil.which("openssl")
        if not openssl:
            # Без OpenSSL CLI — базова валідація відсутня.
            # Можна або відмовитися, або реалізувати власний розбір CMS (складно).
            return False
        with tempfile.TemporaryDirectory() as td:
            data_p = pathlib.Path(td) / "data.bin"
            sig_p = pathlib.Path(td) / "sig.der"
            out_p = pathlib.Path(td) / "out.bin"
            data_p.write_bytes(data)
            sig_p.write_bytes(sig_der)
            # -noverify: не перевіряти ланцюжок, лише підпис/хеш
            cmd = [openssl, "smime", "-verify", "-inform", "DER", "-in", str(sig_p),
                   "-content", str(data_p), "-noverify", "-out", str(out_p)]
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            ok = out_p.read_bytes() == data_p.read_bytes()
            return bool(ok)
    except Exception:
        return False
