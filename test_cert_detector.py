import os
import tempfile
import unittest
import cert_detector


class TestCertDetector(unittest.TestCase):
    def test_parse_target(self):
        # Domain cases
        self.assertEqual(cert_detector.parse_target("example.com"), ("example.com", 443))
        self.assertEqual(cert_detector.parse_target("example.com:8443"), ("example.com", 8443))

        # IPv4 cases
        self.assertEqual(cert_detector.parse_target("192.168.1.1"), ("192.168.1.1", 443))
        self.assertEqual(cert_detector.parse_target("127.0.0.1:9443"), ("127.0.0.1", 9443))

        # IPv6 cases
        self.assertEqual(cert_detector.parse_target("[::1]"), ("::1", 443))
        self.assertEqual(cert_detector.parse_target("[::1]:8443"), ("::1", 8443))
        self.assertEqual(cert_detector.parse_target("[2001:db8::1]:443"), ("2001:db8::1", 443))
        self.assertEqual(cert_detector.parse_target("2001:db8::1"), ("2001:db8::1", 443))

        # Invalid cases
        with self.assertRaises(ValueError):
            cert_detector.parse_target("example.com:abc")
        with self.assertRaises(ValueError):
            cert_detector.parse_target("example.com:0")
        with self.assertRaises(ValueError):
            cert_detector.parse_target("example.com:70000")
        with self.assertRaises(ValueError):
            cert_detector.parse_target("[::1]:invalid")

    def test_format_digest(self):
        data = b"antigravity test data"
        hex_fp = cert_detector.format_digest(data, 'hex')
        b64_fp = cert_detector.format_digest(data, 'base64')

        self.assertEqual(len(hex_fp), 64)
        self.assertEqual(len(b64_fp), 44)
        self.assertTrue(all(c in "0123456789abcdef" for c in hex_fp))

    def test_pem_and_der_file_parsing(self):
        # Generate dummy self-signed cert for testing using cryptography
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"test.local"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).sign(key, hashes.SHA256())

        der_bytes = cert.public_bytes(Encoding.DER)
        pem_bytes = cert.public_bytes(Encoding.PEM)

        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f_pem:
            f_pem.write(pem_bytes)
            pem_path = f_pem.name

        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f_der:
            f_der.write(der_bytes)
            der_path = f_der.name

        try:
            parsed_der_from_pem = cert_detector.get_cert_der_from_file(pem_path)
            parsed_der_from_der = cert_detector.get_cert_der_from_file(der_path)

            self.assertEqual(parsed_der_from_pem, der_bytes)
            self.assertEqual(parsed_der_from_der, der_bytes)

            spki_der = cert_detector.get_pubkey_der_from_cert_der(parsed_der_from_pem)
            self.assertTrue(len(spki_der) > 0)
        finally:
            if os.path.exists(pem_path):
                os.remove(pem_path)
            if os.path.exists(der_path):
                os.remove(der_path)


if __name__ == '__main__':
    unittest.main()
