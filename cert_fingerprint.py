#!/usr/bin/env python3
"""
Backward compatibility wrapper for cert_fingerprint.py.
Delegates all functionality to cert_detector.py.
"""
import cert_detector

# Re-export main APIs for backward compatibility
parse_target = cert_detector.parse_target
format_digest = cert_detector.format_digest
get_cert_der_from_domain = cert_detector.get_cert_der_from_domain
get_cert_ders_from_domain = cert_detector.get_cert_ders_from_domain
get_cert_der_from_file = cert_detector.get_cert_der_from_file
get_cert_ders_from_file = cert_detector.get_cert_ders_from_file
get_pubkey_der_from_cert_der = cert_detector.get_pubkey_der_from_cert_der
output_fingerprints = cert_detector.output_fingerprints
main = cert_detector.main

if __name__ == '__main__':
    main()
