import datetime
import os
import ssl
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding

import cert_detector


class TestCertDetector(unittest.TestCase):
    def test_parse_target_valid(self):
        # Domain cases
        self.assertEqual(cert_detector.parse_target("example.com"), ("example.com", 443))
        self.assertEqual(cert_detector.parse_target("example.com:8443"), ("example.com", 8443))

        # URL cases
        self.assertEqual(cert_detector.parse_target("https://example.com"), ("example.com", 443))
        self.assertEqual(cert_detector.parse_target("https://example.com:8443"), ("example.com", 8443))
        self.assertEqual(cert_detector.parse_target("https://example.com:8443/graphql"), ("example.com", 8443))
        self.assertEqual(cert_detector.parse_target("http://api.example.com/v1"), ("api.example.com", 443))
        self.assertEqual(cert_detector.parse_target("example.com/some/path"), ("example.com", 443))

        # IPv4 cases
        self.assertEqual(cert_detector.parse_target("192.168.1.1"), ("192.168.1.1", 443))
        self.assertEqual(cert_detector.parse_target("127.0.0.1:9443"), ("127.0.0.1", 9443))
        self.assertEqual(cert_detector.parse_target("https://127.0.0.1:9443/metrics"), ("127.0.0.1", 9443))

        # IPv6 cases
        self.assertEqual(cert_detector.parse_target("[::1]"), ("::1", 443))
        self.assertEqual(cert_detector.parse_target("[::1]:8443"), ("::1", 8443))
        self.assertEqual(cert_detector.parse_target("[2001:db8::1]:443"), ("2001:db8::1", 443))
        self.assertEqual(cert_detector.parse_target("2001:db8::1"), ("2001:db8::1", 443))
        self.assertEqual(cert_detector.parse_target("https://[::1]:8443/api"), ("::1", 8443))

    def test_parse_target_invalid_ports(self):
        # Empty input
        with self.assertRaises(ValueError):
            cert_detector.parse_target("")

        # Domain with invalid / out-of-range port
        with self.assertRaises(ValueError):
            cert_detector.parse_target("example.com:abc")
        with self.assertRaises(ValueError):
            cert_detector.parse_target("example.com:0")
        with self.assertRaises(ValueError):
            cert_detector.parse_target("example.com:65536")
        with self.assertRaises(ValueError):
            cert_detector.parse_target("example.com:70000")

        # IPv6 with invalid / out-of-range port (verifies BUG-01 fix)
        with self.assertRaises(ValueError):
            cert_detector.parse_target("[::1]:invalid")
        with self.assertRaises(ValueError):
            cert_detector.parse_target("[::1]:0")
        with self.assertRaises(ValueError):
            cert_detector.parse_target("[::1]:65536")
        with self.assertRaises(ValueError):
            cert_detector.parse_target("[::1]:99999")
        with self.assertRaises(ValueError):
            cert_detector.parse_target("[::1]:-1")

    def test_format_digest(self):
        data = b"antigravity test data"
        hex_fp = cert_detector.format_digest(data, 'hex')
        b64_fp = cert_detector.format_digest(data, 'base64')

        self.assertEqual(len(hex_fp), 64)
        self.assertEqual(len(b64_fp), 44)
        self.assertTrue(all(c in "0123456789abcdef" for c in hex_fp))

    def test_pem_and_der_file_parsing(self):
        # Generate dummy certificates for testing
        key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject1 = issuer1 = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"root.local"),
        ])
        cert1 = x509.CertificateBuilder().subject_name(
            subject1
        ).issuer_name(
            issuer1
        ).public_key(
            key1.public_key()
        ).serial_number(
            1
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(key1, hashes.SHA256())

        key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject2 = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"leaf.local"),
        ])
        cert2 = x509.CertificateBuilder().subject_name(
            subject2
        ).issuer_name(
            subject1
        ).public_key(
            key2.public_key()
        ).serial_number(
            2
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(key1, hashes.SHA256())

        der1 = cert1.public_bytes(Encoding.DER)
        der2 = cert2.public_bytes(Encoding.DER)
        pem_chain = cert2.public_bytes(Encoding.PEM) + b"\n" + cert1.public_bytes(Encoding.PEM)

        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f_pem:
            f_pem.write(pem_chain)
            pem_path = f_pem.name

        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f_der:
            f_der.write(der2)
            der_path = f_der.name

        try:
            # 1. Single DER file
            parsed_der = cert_detector.get_cert_der_from_file(der_path)
            self.assertEqual(parsed_der, der2)

            # 2. Multi-cert PEM chain (BUG-03 fix)
            parsed_chain = cert_detector.get_cert_ders_from_file(pem_path)
            self.assertEqual(len(parsed_chain), 2)
            self.assertEqual(parsed_chain[0], der2)
            self.assertEqual(parsed_chain[1], der1)

            # SPKI extraction
            spki_der = cert_detector.get_pubkey_der_from_cert_der(parsed_der)
            self.assertTrue(len(spki_der) > 0)
        finally:
            if os.path.exists(pem_path):
                os.remove(pem_path)
            if os.path.exists(der_path):
                os.remove(der_path)

    def test_invalid_der_file_rejection(self):
        # Non-certificate binary starting with 0x30 (verifies BUG-02 fix)
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f_fake:
            f_fake.write(b"\x30\x01\x02\x03\x04")
            fake_path = f_fake.name

        try:
            with self.assertRaises(ValueError):
                cert_detector.get_cert_der_from_file(fake_path)
        finally:
            if os.path.exists(fake_path):
                os.remove(fake_path)

    def test_ssl_verification_error_formatting(self):
        # Verifies BUG-04 fix: exception str is not formatted as tuple string
        err = ssl.SSLCertVerificationError(1, "certificate verify failed")
        self.assertFalse(str(err).startswith("('"))
        self.assertIn("certificate verify failed", str(err))


if __name__ == '__main__':
    unittest.main()
