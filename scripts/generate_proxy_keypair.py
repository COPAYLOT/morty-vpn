"""Generate the shared Ed25519/X25519 keypair that the Morty proxy
Apps Script hardcodes. Run this ONCE; copy the printed values into
`HARDCODED_ED25519_PUB_PEM` and `HARDCODED_X25519_PRIV_B64` in
`scripts/morty_proxy.gs` and re-deploy.

NEVER regenerate the keypair. Proton's certificate is bound to this
public key — rotating it invalidates the cert for every user of the
script deployment.

Run:
    pip install cryptography pynacl
    python scripts/generate_proxy_keypair.py
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import nacl.bindings


def main() -> None:
    ed_priv = Ed25519PrivateKey.generate()
    raw_priv = ed_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub = ed_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # libsodium: full ed25519 sk = seed (32) || pub (32)
    x_priv = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(raw_priv + raw_pub)

    # PEM (SubjectPublicKeyInfo) for the Ed25519 public key
    pem = ed_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    x_b64 = base64.b64encode(x_priv).decode("ascii")

    print("=" * 72)
    print("PASTE INTO scripts/morty_proxy.gs")
    print("=" * 72)
    print()
    print("const HARDCODED_ED25519_PUB_PEM =")
    for i in range(0, len(pem), 64):
        print(f"  {pem[i:i+64].rstrip()}\\")
    print(";")
    print()
    print(f"const HARDCODED_X25519_PRIV_B64 = \"{x_b64}\";")
    print()
    print("=" * 72)
    print("FINGERPRINT (sha256 of x_priv, base64):")
    import hashlib
    print("  " + base64.b64encode(hashlib.sha256(x_priv).digest()).decode())
    print("=" * 72)


if __name__ == "__main__":
    main()
