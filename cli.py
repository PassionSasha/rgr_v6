from __future__ import annotations
import argparse, sys, pathlib, json
from hybrid_crypto import KDFParams as KDF1, hybrid_encrypt, hybrid_decrypt
from secure_store import SecureStoreV6, KDFParams as KDF2
from x509_tools import gen_keypair, save_pem_priv, save_pem_pub, make_csr, save_csr_pem, selfsign, save_cert_pem, export_pfx, pfx_to_pem, import_cert_windows_store
from signing import sign_detached_raw, verify_detached_raw, sign_pkcs7_detached, verify_pkcs7_detached


# ----------------------------
# Базові encrypt / decrypt
# ----------------------------
def cmd_encrypt(args):
    data = pathlib.Path(args.in_path).read_bytes()
    aad = args.aad.encode("utf-8") if args.aad else None

    if args.key_method == "pbkdf2":
        if not args.passphrase:
            print("ERROR: --passphrase is required for pbkdf2", file=sys.stderr)
            sys.exit(2)
        salt = bytes.fromhex(args.salt_hex) if args.salt_hex else None
        kdf = KDF1(method="pbkdf2", passphrase=args.passphrase.encode("utf-8"),
                   salt=salt, iterations=args.iterations)
    else:
        kdf = KDF1(method="random")

    blob = hybrid_encrypt(plaintext=data, pubkey_pem=args.pub, kdf_params=kdf, aad=aad)
    pathlib.Path(args.out_path).write_bytes(blob)
    print(f"Encrypted -> {args.out_path}")

def cmd_decrypt(args):
    blob = pathlib.Path(args.in_path).read_bytes()
    passphrase = args.passphrase.encode("utf-8") if args.passphrase else None
    pt = hybrid_decrypt(container=blob, privkey_pem=args.priv, passphrase_for_pbkdf2=passphrase)
    pathlib.Path(args.out_path).write_bytes(pt)
    print(f"Decrypted -> {args.out_path}")

# ----------------------------
# SecureStore V6 put / get
# ----------------------------
def cmd_storev6_put(args):
    data = pathlib.Path(args.in_path).read_bytes()
    store = SecureStoreV6(args.vault)
    if args.key_method == "pbkdf2":
        if not args.passphrase:
            print("ERROR: --passphrase is required for pbkdf2", file=sys.stderr)
            sys.exit(2)
        salt = bytes.fromhex(args.salt_hex) if args.salt_hex else None
        kdf = KDF2(method="pbkdf2",
                   passphrase=args.passphrase.encode("utf-8"),
                   salt=salt,
                   iterations=args.iterations)
    else:
        kdf = KDF2(method="random")
    aad = args.aad.encode("utf-8") if args.aad else None
    meta = json.loads(args.meta) if args.meta else None
    rid = store.put(data, args.pub, kdf=kdf, aad=aad, user_meta=meta)
    print(rid)

def cmd_storev6_get(args):
    store = SecureStoreV6(args.vault)
    passb = args.passphrase.encode("utf-8") if args.passphrase else None
    pt, _ = store.get(args.id, args.priv, passphrase_for_pbkdf2=passb)
    pathlib.Path(args.out_path).write_bytes(pt)
    print("OK")

def cmd_x509_gen(args):
    priv, pub = gen_keypair(args.alg, args.bits)
    save_pem_priv(priv, args.out_priv, args.passphrase.encode("utf-8") if args.passphrase else None)
    save_pem_pub(pub, args.out_pub)
    print("OK")

def cmd_x509_csr(args):
    data = pathlib.Path(args.priv).read_bytes()
    priv = serialization.load_pem_private_key(data, password=(args.passphrase.encode("utf-8") if args.passphrase else None))
    csr = make_csr(priv, args.cn, args.org, args.country, args.san)
    save_csr_pem(csr, args.out)
    print("CSR saved")

def cmd_x509_selfsign(args):
    data = pathlib.Path(args.priv).read_bytes()
    priv = serialization.load_pem_private_key(data, password=(args.passphrase.encode("utf-8") if args.passphrase else None))
    cert = selfsign(priv, args.cn, args.days)
    save_cert_pem(cert, args.out_cert)
    if args.pfx:
        export_pfx(priv, cert, [], (args.pfx_pass or "changeit").encode("utf-8"), args.pfx)
    print("Certificate saved")

def cmd_x509_pfx_to_pem(args):
    pfx_to_pem(args.pfx, args.out_priv, args.out_cert, password=(args.pfx_pass.encode("utf-8") if args.pfx_pass else None))
    print("PEM exported")

def cmd_x509_import_win(args):
    import_cert_windows_store(args.cert, args.store)
    print("Imported into Windows store")

# ----------------------------
# Підпис / Перевірка
# ----------------------------
def cmd_sign_raw(args):
    data = pathlib.Path(args.in_path).read_bytes()
    sig = sign_detached_raw(data, args.priv, args.alg, password=(args.passphrase.encode("utf-8") if args.passphrase else None))
    pathlib.Path(args.out_sig).write_bytes(sig)
    print("OK")

def cmd_verify_raw(args):
    data = pathlib.Path(args.in_path).read_bytes()
    sig = pathlib.Path(args.sig).read_bytes()
    ok = verify_detached_raw(data, sig, args.pub, args.alg)
    print("VALID" if ok else "INVALID")
    sys.exit(0 if ok else 1)

def cmd_sign_pkcs7(args):
    data = pathlib.Path(args.in_path).read_bytes()
    sig = sign_pkcs7_detached(data, args.priv, args.cert, password=(args.passphrase.encode("utf-8") if args.passphrase else None))
    pathlib.Path(args.out_sig).write_bytes(sig)
    print("OK (DER PKCS#7)")

def cmd_verify_pkcs7(args):
    data = pathlib.Path(args.in_path).read_bytes()
    sig = pathlib.Path(args.sig).read_bytes()
    ok = verify_pkcs7_detached(data, sig)
    print("VALID" if ok else "INVALID")
    sys.exit(0 if ok else 1)

# ----------------------------
# CLI
# ----------------------------
def main():
    p = argparse.ArgumentParser(description="RGR Variant 6: AES-CCM(128)+RSA-OAEP(2048)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # encrypt
    pe = sub.add_parser("encrypt", help="encrypt a file into header+payload container")
    pe.add_argument("--in", dest="in_path", required=True)
    pe.add_argument("--out", dest="out_path", required=True)
    pe.add_argument("--pub", required=True, help="path to RSA public key (PEM)")
    pe.add_argument("--key-method", choices=["random","pbkdf2"], default="random")
    pe.add_argument("--passphrase")
    pe.add_argument("--salt-hex")
    pe.add_argument("--iterations", type=int, default=300000)
    pe.add_argument("--aad", help="associated data (optional)")
    pe.set_defaults(func=cmd_encrypt)

    # decrypt
    pd = sub.add_parser("decrypt", help="decrypt a header+payload container")
    pd.add_argument("--in", dest="in_path", required=True)
    pd.add_argument("--out", dest="out_path", required=True)
    pd.add_argument("--priv", required=True, help="path to RSA private key (PEM)")
    pd.add_argument("--passphrase", help="required if container was created with pbkdf2")
    pd.set_defaults(func=cmd_decrypt)

    # storev6-put
    sp = sub.add_parser("storev6-put", help="Put into RGR6 secure store (AES-CCM128 + RSA-OAEP)")
    sp.add_argument("--vault", required=True)
    sp.add_argument("--in", dest="in_path", required=True)
    sp.add_argument("--pub", required=True)
    sp.add_argument("--key-method", choices=["random","pbkdf2"], default="random")
    sp.add_argument("--passphrase")
    sp.add_argument("--salt-hex")
    sp.add_argument("--iterations", type=int, default=300000)
    sp.add_argument("--aad")
    sp.add_argument("--meta", help='JSON string of user metadata')
    sp.set_defaults(func=cmd_storev6_put)

    # storev6-get
    sg = sub.add_parser("storev6-get", help="Get from RGR6 secure store")
    sg.add_argument("--vault", required=True)
    sg.add_argument("--id", required=True)
    sg.add_argument("--priv", required=True)
    sg.add_argument("--out", dest="out_path", required=True)
    sg.add_argument("--passphrase", help="needed if PBKDF2 was used")
    sg.set_defaults(func=cmd_storev6_get)

    # --- X.509 ---
    xg = sub.add_parser("x509-gen", help="Generate keypair (RSA/ECDSA)")
    xg.add_argument("--alg", choices=["rsa","ecdsa"], default="rsa")
    xg.add_argument("--bits", type=int, default=2048)
    xg.add_argument("--out-priv", required=True)
    xg.add_argument("--out-pub", required=True)
    xg.add_argument("--passphrase")
    xg.set_defaults(func=cmd_x509_gen)

    xc = sub.add_parser("x509-csr", help="Create CSR")
    xc.add_argument("--priv", required=True)
    xc.add_argument("--passphrase")
    xc.add_argument("--cn", required=True)
    xc.add_argument("--org", default="Org")
    xc.add_argument("--country", default="UA")
    xc.add_argument("--san", nargs="*")
    xc.add_argument("--out", required=True)
    xc.set_defaults(func=cmd_x509_csr)

    xs = sub.add_parser("x509-selfsign", help="Self-signed certificate")
    xs.add_argument("--priv", required=True)
    xs.add_argument("--passphrase")
    xs.add_argument("--cn", required=True)
    xs.add_argument("--days", type=int, default=365)
    xs.add_argument("--out-cert", required=True)
    xs.add_argument("--pfx")
    xs.add_argument("--pfx-pass")
    xs.set_defaults(func=cmd_x509_selfsign)

    xp = sub.add_parser("x509-pfx-to-pem", help="Export PEM from PFX")
    xp.add_argument("--pfx", required=True)
    xp.add_argument("--pfx-pass")
    xp.add_argument("--out-priv", required=True)
    xp.add_argument("--out-cert", required=True)
    xp.set_defaults(func=cmd_x509_pfx_to_pem)

    xi = sub.add_parser("x509-import-win", help="Import cert into Windows store")
    xi.add_argument("--cert", required=True)
    xi.add_argument("--store", default="My")
    xi.set_defaults(func=cmd_x509_import_win)

    # --- Sign (raw detached) ---
    sr = sub.add_parser("sign-raw", help="Detached RAW signature (rsa-pss|ecdsa-p256)")
    sr.add_argument("--in", dest="in_path", required=True)
    sr.add_argument("--priv", required=True)
    sr.add_argument("--alg", choices=["rsa-pss","ecdsa-p256"], default="rsa-pss")
    sr.add_argument("--passphrase")
    sr.add_argument("--out-sig", required=True)
    sr.set_defaults(func=cmd_sign_raw)

    vr = sub.add_parser("verify-raw", help="Verify RAW detached signature")
    vr.add_argument("--in", dest="in_path", required=True)
    vr.add_argument("--sig", required=True)
    vr.add_argument("--pub", required=True)
    vr.add_argument("--alg", choices=["rsa-pss","ecdsa-p256"], default="rsa-pss")
    vr.set_defaults(func=cmd_verify_raw)

    # --- Sign (PKCS#7/CMS detached) ---
    sp7 = sub.add_parser("sign-pkcs7", help="Detached PKCS#7 (CMS) signature (DER)")
    sp7.add_argument("--in", dest="in_path", required=True)
    sp7.add_argument("--priv", required=True, help="signer private key (PEM)")
    sp7.add_argument("--cert", required=True, help="signer certificate (PEM)")
    sp7.add_argument("--passphrase")
    sp7.add_argument("--out-sig", required=True)
    sp7.set_defaults(func=cmd_sign_pkcs7)

    vp7 = sub.add_parser("verify-pkcs7", help="Verify detached PKCS#7 (CMS) signature")
    vp7.add_argument("--in", dest="in_path", required=True)
    vp7.add_argument("--sig", required=True, help="DER PKCS#7")
    vp7.set_defaults(func=cmd_verify_pkcs7)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
