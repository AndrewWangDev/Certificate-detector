#!/usr/bin/env python3
"""
Backward compatibility wrapper for cert_fingerprint.py.
Delegates all functionality to cert_detector.py.
"""
from cert_detector import *

if __name__ == '__main__':
    main()
