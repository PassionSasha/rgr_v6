from __future__ import annotations
import argparse
import datetime
import pathlib
import subprocess
import sys
from typing import Optional, List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec


# ---------------------------
# Генерація ключової пари
# ---------------------------
def gen_keypair(alg: str = "rsa", bits: int = 2048):
    if alg == "rsa":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    elif alg == "ecdsa":
        priv = ec.generate_private_key(ec.SECP256R1())  # P-256
    else:
        raise ValueError("alg must be 'rsa' or 'ecdsa'")
    return priv, priv.public_key()


def save_pem_priv(priv, path: str, password: Optional[bytes] = None):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        enc
    )
    pathlib.Path(path).write_bytes(pem)


def save_pem_pub(pub, path: str):
    pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pathlib.Path(path).write_bytes(pem)


# ---------------------------
# CSR (Certificate Signing Request)
# ---------------------------
def make_csr(priv, cn: str, org: str = "Org", country: str = "UA", san_dns: Optional[List[str]] = None):
    name = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, cn),
    ])
    builder = x509.CertificateSigningRequestBuilder().subject_name(name)
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
            critical=False
        )
    csr = builder.sign(priv, hashes.SHA256())
    return csr


def save_csr_pem(csr, path: str):
    pathlib.Path(path).write_bytes(csr.public_bytes(serialization.Encoding.PEM))


# ---------------------------
# Самопідписаний сертифікат (для тестів/демо)
# ---------------------------
def selfsign(priv, subject_cn: str, days: int = 365):
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_cn)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(priv, hashes.SHA256())
    )
    return cert


def save_cert_pem(cert, path: str):
    pathlib.Path(path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


# ---------------------------
# PKCS#12 (PFX)
# ---------------------------
def export_pfx(priv, cert, chain: list = None, password: bytes = b"changeit", path: str = "bundle.pfx"):
    from cryptography.hazmat.primitives.serialization import pkcs12
    blob = pkcs12.serialize_key_and_certificates(
        name=b"rgr6",
        key=priv,
        cert=cert,
        cas=chain or [],
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    pathlib.Path(path).write_bytes(blob)


def pfx_to_pem(pfx_path: str, out_priv_pem: str, out_cert_pem: str, password: Optional[bytes]):
    from cryptography.hazmat.primitives.serialization import pkcs12
    data = pathlib.Path(pfx_path).read_bytes()
    priv, cert, chain = pkcs12.load_key_and_certificates(data, password=password)
    if priv:
        save_pem_priv(priv, out_priv_pem, password=None)
    if cert:
        save_cert_pem(cert, out_cert_pem)
    # ланцюг (якщо є) можна теж зберегти за потреби


# ---------------------------
# Імпорт у Windows Cert Store (через certutil)
# ---------------------------
def import_cert_windows_store(cert_pem_path: str, store_name: str = "My"):
    if sys.platform != "win32":
        raise RuntimeError("Імпорт у Windows Cert Store доступний лише на Windows")
    # certutil додає серт у задане сховище (наприклад, 'My' = Personal)
    subprocess.check_call(["certutil", "-addstore", "-f", store_name, cert_pem_path], shell=False)


# ---------------------------
# CLI для цього модуля (необов'язково)
# ---------------------------
def _main():
    ap = argparse.ArgumentParser(description="X.509 tools")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="Generate keypair")
    g.add_argument("--alg", choices=["rsa","ecdsa"], default="rsa")
    g.add_argument("--bits", type=int, default=2048)
    g.add_argument("--out-priv", required=True)
    g.add_argument("--out-pub", required=True)
    g.add_argument("--passphrase", help="protect private key PEM")
    g.set_defaults(func="gen")

    c = sub.add_parser("csr", help="Create CSR")
    c.add_argument("--priv", required=True)
    c.add_argument("--passphrase")
    c.add_argument("--cn", required=True)
    c.add_argument("--org", default="Org")
    c.add_argument("--country", default="UA")
    c.add_argument("--san", nargs="*")
    c.add_argument("--out", required=True)
    c.set_defaults(func="csr")

    s = sub.add_parser("selfsign", help="Create self-signed certificate")
    s.add_argument("--priv", required=True)
    s.add_argument("--passphrase")
    s.add_argument("--cn", required=True)
    s.add_argument("--days", type=int, default=365)
    s.add_argument("--out-cert", required=True)
    s.add_argument("--pfx")
    s.add_argument("--pfx-pass")
    s.set_defaults(func="selfsign")

    pfx = sub.add_parser("pfx-to-pem", help="Export PEM from PFX")
    pfx.add_argument("--pfx", required=True)
    pfx.add_argument("--pfx-pass")
    pfx.add_argument("--out-priv", required=True)
    pfx.add_argument("--out-cert", required=True)
    pfx.set_defaults(func="pfx")

    iw = sub.add_parser("import-win", help="Import cert into Windows store")
    iw.add_argument("--cert", required=True)
    iw.add_argument("--store", default="My")
    iw.set_defaults(func="importwin")

    args = ap.parse_args()
    if args.func == "gen":
        priv, pub = gen_keypair(args.alg, args.bits)
        save_pem_priv(priv, args.out_priv, args.passphrase.encode("utf-8") if args.passphrase else None)
        save_pem_pub(pub, args.out_pub)
        print("OK")
    elif args.func == "csr":
        data = pathlib.Path(args.priv).read_bytes()
        priv = serialization.load_pem_private_key(data, password=(args.passphrase.encode("utf-8") if args.passphrase else None))
        csr = make_csr(priv, args.cn, args.org, args.country, args.san)
        save_csr_pem(csr, args.out)
        print("CSR saved")
    elif args.func == "selfsign":
        data = pathlib.Path(args.priv).read_bytes()
        priv = serialization.load_pem_private_key(data, password=(args.passphrase.encode("utf-8") if args.passphrase else None))
        cert = selfsign(priv, args.cn, args.days)
        save_cert_pem(cert, args.out_cert)
        if args.pfx:
            export_pfx(priv, cert, [], (args.pfx_pass or "changeit").encode("utf-8"), args.pfx)
        print("Certificate saved")
    elif args.func == "pfx":
        pfx_to_pem(args.pfx, args.out_priv, args.out_cert, password=(args.pfx_pass.encode("utf-8") if args.pfx_pass else None))
        print("PEM exported")
    elif args.func == "importwin":
        import_cert_windows_store(args.cert, args.store)
        print("Imported")


if __name__ == "__main__":
    _main()
