# Certificate Detector

<p align="center">
  <a href="https://github.com/AndrewWangDev/Certificate-detector/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/AndrewWangDev/Certificate-detector.svg?style=flat-square" alt="License">
  </a>
  <img src="https://img.shields.io/badge/python-3.6%2B-blue.svg?style=flat-square" alt="Python Version">
  <img src="https://img.shields.io/badge/security-pinning-success.svg?style=flat-square" alt="Security: Pinning">
</p>

> Automatically extracts the SHA-256 fingerprints of TLS certificates and public keys from domain names and local certificate files (.pem, .crt, .der), useful for certificate/SPKI pinning and proxy client debugging.

## 📖 Overview

Implementing **Client-Side Certificate or Public Key Pinning** requires embedding precise cryptographic hashes into your application. Traditionally, extracting these hashes demands complex, multi-step `openssl` command chains. 

**Certificate Detector** automates this workflow. Whether you need to inspect a live production server, an interception proxy, or parse a local PEM/DER file, this tool provides standardized, pinning-ready fingerprints in a single command.

---

## ✨ Key Features

* **Live Server Inspection:** Directly connect to remote endpoints (IPv4, IPv6, domains) and extract peer certificates via TLS handshakes.
* **Local File Parsing:** Robust parsing of local `.pem`, `.crt`, or binary `.der` certificate files.
* **SPKI Extraction:** Automatically computes Subject Public Key Info (SPKI) fingerprints, recommended for resilient pinning strategies.
* **Multiple Output Formats:** Supports both standard hexadecimal (Hex) and Base64 formats (ready for Android, iOS, and OkHttp).
* **Insecure Mode for Proxies / Self-Signed:** Inspect servers with self-signed certificates or debugging proxies without TLS verification errors.
* **Highly Configurable:** Granular control over target ports, connection timeouts, SNI override, and output verbosity.
* **Zero OS Dependencies:** Runs on any OS with Python, bypassing the need for native OpenSSL binaries.

---

## 📸 Demo

Testing the fingerprint extraction against a live domain:

![Domain Testing Execution](Test.png)

---

## ⚙️ Installation

**Prerequisites:** Python 3.6+

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/AndrewWangDev/Certificate-detector.git
    cd Certificate-detector
    ```

2.  *(Optional but recommended)* **Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install the required cryptography package:**
    ```bash
    pip install -r requirements.txt
    ```

---

## 🚀 Usage Guide

### Display Help Menu
```bash
python cert_detector.py --help
```
*(Note: `python cert_fingerprint.py` is also maintained as an alias for backward compatibility).*

### 1. Remote Domain Extraction (Standard Port 443)
Fetch both the full Certificate Hash and the Public Key Hash from a remote host:
```bash
python cert_detector.py --domain example.com
```
*Output:*
```text
cert:WoiBE123456...
pubkey:A1b2C3d4E5...
```

### 2. Base64 Format for Android / OkHttp Pinning
Mobile frameworks (Android `network_security_config.xml`, OkHttp, iOS) require Base64-encoded hashes:
```bash
python cert_detector.py -d example.com -o pubkey --format base64
```
*Output:*
```text
47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```

### 3. Remote Domain with Custom Port & Timeout
Specify a non-standard port and adjust the network timeout (in seconds):
```bash
python cert_detector.py -d myapi.example.com:8443 --timeout 10.0
```

### 4. Self-Signed Certificates & Proxy Debugging
Bypass strict TLS CA verification when testing self-signed certificates, private CAs, or proxy environments:
```bash
python cert_detector.py -d self-signed.local -k
```

### 5. IPv6 Targets
Supports IPv6 addresses with or without brackets and custom ports:
```bash
python cert_detector.py -d [::1]:8443
```

### 6. Local Certificate File Parsing
Extract fingerprints from a local `.pem`, `.crt`, or binary `.der` file:
```bash
python cert_detector.py --file ./certs/production_cert.pem
```

---

## 🧰 Command-Line Arguments

| Flag | Short | Description | Required |
| :--- | :--- | :--- | :--- |
| `--domain` | `-d` | Target domain, IP (IPv4/IPv6), or host:port (e.g. `api.com:443`, `[::1]:8443`). | Mutually exclusive with `--file`. |
| `--file` | `-f` | Path to a local PEM, CRT, or binary DER certificate file. | Mutually exclusive with `--domain`. |
| `--timeout` | `-t` | TLS handshake timeout in seconds (Default: `5.0`). | No |
| `--output` | `-o` | Define output mode: `cert`, `pubkey`, or `both` (Default: `both`). | No |
| `--format` | | Hash encoding format: `hex` or `base64` (Default: `hex`). | No |
| `--insecure` | `-k` | Disable TLS certificate verification (useful for self-signed certs or proxy analysis). | No |
| `--sni` | | Override TLS Server Name Indication (SNI) hostname. | No |

---

## 🛡️ Security Best Practices

When implementing pinning in production applications (e.g., iOS, Android, or IoT clients):

1.  **Prefer Public Key Pinning:** Pinning the `pubkey` prevents unexpected application outages when a CA rotates the server's certificate, provided the same Private Key is used to generate the new CSR.
2.  **Backup Pins:** Always include a backup pin (a fingerprint of a secondary key held securely offline) to ensure availability if your primary key is compromised.

---

## 📄 License

This project is open-sourced under the [MIT License](LICENSE).
