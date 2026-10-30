#!/usr/bin/env python3
"""
Certificate Detector
Computes SHA-256 fingerprints of certificates and Subject Public Key Info (SPKI)
from live remote domains or local certificate files (.pem, .crt, .der).
"""
import argparse
import base64
import hashlib
import ipaddress
import re
import socket
import ssl
import sys
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    CRYPTOGRAPHY_AVAILABLE = True
except Exception:
    CRYPTOGRAPHY_AVAILABLE = False


def format_digest(der_bytes: bytes, fmt: str = 'hex') -> str:
    """Format raw DER bytes into a SHA-256 hex or base64 string."""
    digest = hashlib.sha256(der_bytes).digest()
    if fmt == 'base64':
        return base64.b64encode(digest).decode('ascii')
    return digest.hex()


def parse_target(target: str) -> Tuple[str, int]:
    """
    Robustly parse target into (hostname_or_ip, port).
    Supports URLs, domain names, IPv4, IPv6 ([::1]:port or bare ::1), and custom ports.
    """
    target = target.strip()
    if not target:
        raise ValueError("Target host/domain cannot be empty.")

    # 1. Handle URLs (e.g. https://example.com:8443/path -> example.com:8443)
    if '://' in target:
        parsed = urlsplit(target)
        target = parsed.netloc or parsed.path
    elif '/' in target:
        target = target.split('/', 1)[0]

    port = 443

    # 2. Bracketed IPv6 notation: [::1]:8443 or [::1]
    if target.startswith('['):
        if ']:' in target:
            host_part, port_s = target.split(']:', 1)
            hostname = host_part.lstrip('[')
            try:
                port = int(port_s)
            except ValueError:
                raise ValueError(f"Could not parse port from '{target}'")
        else:
            hostname = target.strip('[]')
            port = 443
    else:
        # 3. Check if target is a bare IPv6 address without brackets
        try:
            ipaddress.IPv6Address(target)
            return target, 443
        except ValueError:
            pass

        # 4. Standard host:port or IPv4:port
        if ':' in target:
            host_part, port_s = target.rsplit(':', 1)
            try:
                port = int(port_s)
            except ValueError:
                raise ValueError(f"Could not parse port from '{target}'")
            hostname = host_part
        else:
            hostname = target
            port = 443

    # 5. Global port range validation for all targets (including IPv6)
    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got {port}")

    return hostname, port


def get_cert_ders_from_domain(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
    insecure: bool = False,
    sni: Optional[str] = None
) -> List[bytes]:
    """
    Connect to a remote host via TLS and retrieve the peer certificates in DER format.
    Returns a list of certificates (leaf certificate first, followed by intermediate/chain certificates if available).
    Supports insecure mode (bypasses CA verification for self-signed/proxy certs)
    and custom SNI overrides.
    """
    if insecure:
        ctx = ssl._create_unverified_context()
    else:
        ctx = ssl.create_default_context()

    if sni:
        server_hostname = sni
    else:
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            pass

        if is_ip and insecure:
            server_hostname = None
        else:
            server_hostname = hostname

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                # Python 3.13+ supports retrieving full certificate chains
                if insecure and hasattr(ssock, 'get_unverified_chain'):
                    chain = ssock.get_unverified_chain()
                    if chain:
                        return list(chain)
                elif hasattr(ssock, 'get_verified_chain'):
                    chain = ssock.get_verified_chain()
                    if chain:
                        return list(chain)

                # Fallback: retrieve the peer leaf certificate
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    raise ValueError("Could not retrieve peer certificate (binary_form returned empty)")
                return [der]
    except socket.timeout:
        raise TimeoutError(f"Connection timed out while connecting to {hostname}:{port} (timeout={timeout}s)")
    except ssl.SSLCertVerificationError as e:
        msg = f"{e.strerror}. Use --insecure / -k to bypass certificate verification if inspecting self-signed or proxy certificates."
        raise ssl.SSLCertVerificationError(e.errno, msg) from e


def get_cert_der_from_domain(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
    insecure: bool = False,
    sni: Optional[str] = None
) -> bytes:
    """Retrieve the single leaf peer certificate in DER format from a remote host."""
    ders = get_cert_ders_from_domain(hostname, port=port, timeout=timeout, insecure=insecure, sni=sni)
    return ders[0]


def extract_pem_blocks(pem_text: str) -> List[str]:
    """Extract all PEM certificate blocks supporting standard header variations."""
    return re.findall(
        r"-----BEGIN (?:[A-Z0-9_\s]+)?CERTIFICATE-----.*?-----END (?:[A-Z0-9_\s]+)?CERTIFICATE-----",
        pem_text,
        flags=re.DOTALL
    )


def get_cert_ders_from_file(path: str) -> List[bytes]:
    """
    Read certificate DER bytes from a local file.
    Supports PEM (single or multi-cert chain) and raw binary DER (.crt, .der, .pem).
    """
    with open(path, 'rb') as f:
        content = f.read()

    # 1. Use cryptography if available for robust PEM/DER handling
    if CRYPTOGRAPHY_AVAILABLE:
        try:
            certs = x509.load_pem_x509_certificates(content)
            if certs:
                return [c.public_bytes(Encoding.DER) for c in certs]
        except Exception:
            pass

        try:
            cert = x509.load_der_x509_certificate(content)
            return [cert.public_bytes(Encoding.DER)]
        except Exception:
            pass

    # 2. Text PEM fallback
    try:
        text = content.decode('utf-8', errors='ignore')
        pem_blocks = extract_pem_blocks(text)
        if pem_blocks:
            ders = []
            for block in pem_blocks:
                try:
                    der = ssl.PEM_cert_to_DER_cert(block)
                except Exception:
                    body = re.sub(r"-----[^-]+-----|\s+", "", block)
                    der = base64.b64decode(body)
                ders.append(der)
            if ders:
                return ders
    except Exception:
        pass

    # 3. Only if cryptography is NOT available, allow ASN.1 sequence candidate
    if not CRYPTOGRAPHY_AVAILABLE and len(content) > 4 and content[0] == 0x30:
        return [content]

    raise ValueError(f"No valid PEM or DER certificate could be parsed from file '{path}'.")


def get_cert_der_from_file(path: str) -> bytes:
    """Retrieve the first certificate DER bytes from a local file."""
    ders = get_cert_ders_from_file(path)
    return ders[0]


def get_pubkey_der_from_cert_der(der: bytes) -> bytes:
    """Extract Subject Public Key Info (SPKI) DER bytes from a certificate DER."""
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError(
            "The 'cryptography' library is required to extract public key (SPKI) fingerprints. "
            "Install with: pip install cryptography"
        )
    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    return pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def output_fingerprints(ders: List[bytes], output_mode: str, fmt: str, show_chain: bool = False):
    """Compute and display certificate and/or public key fingerprints."""
    targets = ders if show_chain else ders[:1]
    is_multi = len(targets) > 1

    for idx, der in enumerate(targets):
        prefix = f"[{idx}] " if is_multi else ""
        cert_fp = format_digest(der, fmt)
        pub_fp = None

        if output_mode in ('pubkey', 'both'):
            pub_der = get_pubkey_der_from_cert_der(der)
            pub_fp = format_digest(pub_der, fmt)

        if output_mode == 'cert':
            print(f"{prefix}{cert_fp}")
        elif output_mode == 'pubkey':
            print(f"{prefix}{pub_fp}")
        else:  # both
            print(f"{prefix}cert:{cert_fp}")
            print(f"{prefix}pubkey:{pub_fp}")


def main():
    p = argparse.ArgumentParser(
        description="Compute SHA-256 fingerprint of a certificate and SPKI (from domain, URL, or PEM/DER file)"
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--domain', '-d', help='Target domain, URL, IP, or host:port (e.g. example.com, https://api.com:8443, [::1]:443)')
    group.add_argument('--file', '-f', help='Path to local certificate file (.pem, .crt, .der)')

    p.add_argument('--timeout', '-t', type=float, default=5.0, help='Connection timeout in seconds for --domain (default: 5.0)')
    p.add_argument('--output', '-o', choices=['cert', 'pubkey', 'both'], default='both',
                   help='Output mode: certificate only (cert), public key only (pubkey), or both (both) (default: both)')
    p.add_argument('--format', choices=['hex', 'base64'], default='hex',
                   help='Hash encoding format: hex or base64 (default: hex)')
    p.add_argument('--insecure', '-k', action='store_true',
                   help='Disable TLS certificate verification (useful for self-signed certs or proxy endpoints)')
    p.add_argument('--sni', help='Override TLS Server Name Indication (SNI) hostname')
    p.add_argument('--chain', '-c', action='store_true',
                   help='Extract and display fingerprints for all certificates in the chain (Intermediate CAs)')

    args = p.parse_args()

    try:
        if args.domain:
            hostname, port = parse_target(args.domain)
            ders = get_cert_ders_from_domain(
                hostname,
                port=port,
                timeout=args.timeout,
                insecure=args.insecure,
                sni=args.sni
            )
        else:
            ders = get_cert_ders_from_file(args.file)

        output_fingerprints(ders, args.output, args.format, show_chain=args.chain)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
