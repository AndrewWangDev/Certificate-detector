#!/usr/bin/env python3
import argparse
import socket
import ssl
import hashlib
import base64
import re
import sys
from typing import Optional
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    CRYPTOGRAPHY_AVAILABLE = True
except Exception:
    CRYPTOGRAPHY_AVAILABLE = False

def sha256_hex(der_bytes: bytes) -> str:
    return hashlib.sha256(der_bytes).hexdigest()

def get_cert_der_from_domain(hostname: str, port: int = 443, timeout: float = 5.0) -> bytes:
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
            if not der:
                raise ValueError("Could not retrieve peer certificate (binary_form returned empty)")
            return der

def extract_first_pem_block(pem_text: str) -> Optional[str]:
    m = re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        pem_text,
        flags=re.DOTALL
    )
    return m.group(0) if m else None

def get_cert_der_from_pem_file(path: str) -> bytes:
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    pem_block = extract_first_pem_block(text)
    if not pem_block:
        raise ValueError("No PEM certificate block found in file")
    # ssl.PEM_cert_to_DER_cert accepts a PEM string and returns DER bytes
    try:
        der = ssl.PEM_cert_to_DER_cert(pem_block)
    except Exception as e:
        # Fallback: manually base64-decode the PEM body
        body = re.sub(r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+", "", pem_block)
        der = base64.b64decode(body)
    return der

def get_pubkey_der_from_cert_der(der: bytes) -> bytes:
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("cryptography library not installed; cannot extract public key. Install with: pip install cryptography")
    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    pub_der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return pub_der

def main():
    p = argparse.ArgumentParser(description="Compute SHA-256 hex fingerprint of a certificate (from domain or PEM file)")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--domain', '-d', help='Domain or host:port (default port 443)')
    group.add_argument('--file', '-f', help='Local PEM certificate file path')
    p.add_argument('--timeout', '-t', type=float, default=5.0, help='Connection timeout in seconds (only for --domain)')
    p.add_argument('--output', '-o', choices=['cert','pubkey','both'], default='both',
                   help='Output type: certificate fingerprint (cert), public key fingerprint (pubkey), or both (both) (default: both)')
    args = p.parse_args()

    try:
        if args.domain:
            host = args.domain
            if ':' in host:
                hostname, port_s = host.rsplit(':', 1)
                try:
                    port = int(port_s)
                except ValueError:
                    print(f"Could not parse port: {port_s}", file=sys.stderr)
                    sys.exit(2)
            else:
                hostname = host
                port = 443
            der = get_cert_der_from_domain(hostname, port, timeout=args.timeout)
            cert_fp = sha256_hex(der)
            if args.output == 'cert':
                print(cert_fp)
            elif args.output == 'both':
                print(f"cert:{cert_fp}")
            # public key
            if args.output in ('pubkey','both'):
                try:
                    pub_der = get_pubkey_der_from_cert_der(der)
                    pub_fp = sha256_hex(pub_der)
                    if args.output == 'pubkey':
                        print(pub_fp)
                    else:
                        print(f"pubkey:{pub_fp}")
                except Exception as e:
                    print(f"Error: failed to extract public key: {e}", file=sys.stderr)
                    sys.exit(1)
        else:
            der = get_cert_der_from_pem_file(args.file)
            cert_fp = sha256_hex(der)
            if args.output == 'cert':
                print(cert_fp)
            elif args.output == 'both':
                print(f"cert:{cert_fp}")
            if args.output in ('pubkey','both'):
                try:
                    pub_der = get_pubkey_der_from_cert_der(der)
                    pub_fp = sha256_hex(pub_der)
                    #output hex format
                    if args.output == 'pubkey':
                        print(pub_fp)
                    else:
                        print(f"pubkey:{pub_fp}")
                except Exception as e:
                    print(f"Error: failed to extract public key: {e}", file=sys.stderr)
                    sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()