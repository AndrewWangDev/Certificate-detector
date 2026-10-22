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
from typing import Optional, Tuple

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
    Supports domain names, IPv4, IPv6 ([::1]:port or bare ::1), and custom ports.
    """
    target = target.strip()
    if not target:
        raise ValueError("Target host/domain cannot be empty.")

    # Bracketed IPv6 notation: [::1]:8443 or [::1]
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
        return hostname, port

    # Check if target is a bare IPv6 address without brackets
    try:
        ipaddress.IPv6Address(target)
        return target, 443
    except ValueError:
        pass

    # Standard host:port or IPv4:port
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

    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got {port}")

    return hostname, port


def get_cert_der_from_domain(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
    insecure: bool = False,
    sni: Optional[str] = None
) -> bytes:
    """
    Connect to a remote host via TLS and retrieve the peer certificate in DER format.
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
        # Check if hostname is an IP address
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            pass

        # In insecure mode with raw IP, avoid sending IP literal in SNI (RFC 6066)
        if is_ip and insecure:
            server_hostname = None
        else:
            server_hostname = hostname

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if not der:
                    raise ValueError("Could not retrieve peer certificate (binary_form returned empty)")
                return der
    except socket.timeout:
        raise TimeoutError(f"Connection timed out while connecting to {hostname}:{port} (timeout={timeout}s)")
    except ssl.SSLCertVerificationError as e:
        raise ssl.SSLCertVerificationError(
            f"{e.strerror}. Use --insecure / -k to bypass certificate verification if inspecting self-signed or proxy certificates."
        )


def extract_pem_block(pem_text: str) -> Optional[str]:
    """Extract first PEM certificate block supporting standard header variations."""
    m = re.search(
        r"-----BEGIN (?:[A-Z0-9_\s]+)?CERTIFICATE-----.*?-----END (?:[A-Z0-9_\s]+)?CERTIFICATE-----",
        pem_text,
        flags=re.DOTALL
    )
    return m.group(0) if m else None


def get_cert_der_from_file(path: str) -> bytes:
    """
    Read certificate DER bytes from a local file.
    Supports PEM and raw binary DER (.crt, .der, .pem).
    """
    with open(path, 'rb') as f:
        content = f.read()

    # 1. Use cryptography if available for robust PEM/DER handling
    if CRYPTOGRAPHY_AVAILABLE:
        try:
            cert = x509.load_pem_x509_certificate(content)
            return cert.public_bytes(Encoding.DER)
        except Exception:
            pass

        try:
            cert = x509.load_der_x509_certificate(content)
            return cert.public_bytes(Encoding.DER)
        except Exception:
            pass

    # 2. Text PEM fallback
    try:
        text = content.decode('utf-8', errors='ignore')
        pem_block = extract_pem_block(text)
        if pem_block:
            try:
                return ssl.PEM_cert_to_DER_cert(pem_block)
            except Exception:
                body = re.sub(r"-----[^-]+-----|\s+", "", pem_block)
                return base64.b64decode(body)
    except Exception:
        pass

    # 3. Raw DER fallback (begins with ASN.1 Sequence tag 0x30)
    if len(content) > 4 and content[0] == 0x30:
        return content

    raise ValueError(f"No valid PEM or DER certificate could be parsed from file '{path}'.")


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


def output_fingerprints(der: bytes, output_mode: str, fmt: str):
    """Compute and display certificate and/or public key fingerprints."""
    cert_fp = format_digest(der, fmt)
    pub_fp = None

    if output_mode in ('pubkey', 'both'):
        pub_der = get_pubkey_der_from_cert_der(der)
        pub_fp = format_digest(pub_der, fmt)

    if output_mode == 'cert':
        print(cert_fp)
    elif output_mode == 'pubkey':
        print(pub_fp)
    else:  # both
        print(f"cert:{cert_fp}")
        print(f"pubkey:{pub_fp}")


def main():
    p = argparse.ArgumentParser(
        description="Compute SHA-256 fingerprint of a certificate and SPKI (from domain or PEM/DER file)"
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--domain', '-d', help='Target domain, IP, or host:port (e.g. example.com, api.com:8443, [::1]:443)')
    group.add_argument('--file', '-f', help='Path to local certificate file (.pem, .crt, .der)')

    p.add_argument('--timeout', '-t', type=float, default=5.0, help='Connection timeout in seconds for --domain (default: 5.0)')
    p.add_argument('--output', '-o', choices=['cert', 'pubkey', 'both'], default='both',
                   help='Output mode: certificate only (cert), public key only (pubkey), or both (both) (default: both)')
    p.add_argument('--format', choices=['hex', 'base64'], default='hex',
                   help='Hash encoding format: hex or base64 (default: hex)')
    p.add_argument('--insecure', '-k', action='store_true',
                   help='Disable TLS certificate verification (useful for self-signed certs or proxy endpoints)')
    p.add_argument('--sni', help='Override TLS Server Name Indication (SNI) hostname')

    args = p.parse_args()

    try:
        if args.domain:
            hostname, port = parse_target(args.domain)
            der = get_cert_der_from_domain(
                hostname,
                port=port,
                timeout=args.timeout,
                insecure=args.insecure,
                sni=args.sni
            )
        else:
            der = get_cert_der_from_file(args.file)

        output_fingerprints(der, args.output, args.format)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
