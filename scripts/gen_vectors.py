#!/usr/bin/env python3
import os, secrets, subprocess, sys

def openssl_aes128_ecb_encrypt(key_hex: str, pt_hex: str) -> str:
    key = bytes.fromhex(key_hex)
    pt  = bytes.fromhex(pt_hex)
    assert len(key) == 16 and len(pt) == 16

    # OpenSSL enc expects binary in/out. Use -nopad -nosalt for a single block.
    p = subprocess.run(
        ["openssl", "enc", "-aes-128-ecb", "-K", key_hex, "-nosalt", "-nopad"],
        input=pt,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(
            "OpenSSL failed:\n" + p.stderr.decode(errors="ignore")
        )
    ct = p.stdout
    assert len(ct) == 16
    return ct.hex()

def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    out_path = sys.argv[2] if len(sys.argv) > 2 else "vectors.txt"

    # Include the classic known-answer test vector as line 1 (sanity).
    kat_key = "000102030405060708090a0b0c0d0e0f"
    kat_pt  = "00112233445566778899aabbccddeeff"
    kat_ct  = openssl_aes128_ecb_encrypt(kat_key, kat_pt)

    lines = []
    lines.append(f"{kat_key} {kat_pt} {kat_ct}")

    for _ in range(n - 1):
        key_hex = secrets.token_bytes(16).hex()
        pt_hex  = secrets.token_bytes(16).hex()
        ct_hex  = openssl_aes128_ecb_encrypt(key_hex, pt_hex)
        lines.append(f"{key_hex} {pt_hex} {ct_hex}")

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Wrote {len(lines)} vectors to {out_path}")

if __name__ == "__main__":
    main()
