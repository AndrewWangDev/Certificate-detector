# Certificate Detector

<p align="center">
  <a href="https://github.com/AndrewWangDev/Certificate-detector/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/AndrewWangDev/Certificate-detector.svg?style=flat-square" alt="License">
  </a>
  <img src="https://img.shields.io/badge/python-3.6%2B-blue.svg?style=flat-square" alt="Python Version">
  <img src="https://img.shields.io/badge/security-pinning-success.svg?style=flat-square" alt="Security: Pinning">
</p>

> Automatically extracts the SHA-256 fingerprints of TLS certificates and public keys from domain names, full URLs, and local certificate files (.pem, .crt, .der), useful for certificate/SPKI pinning, intermediate CA extraction, and proxy client debugging.

## 📖 Overview

Implementing **Client-Side Certificate or Public Key Pinning** requires embedding precise cryptographic hashes into your application. Traditionally, extracting these hashes demands complex, multi-step `openssl` command chains. 

**Certificate Detector** automates this workflow. Whether you need to inspect a live production server, an interception proxy, or parse a local PEM/DER file (including fullchains), this tool provides standardized, pinning-ready fingerprints in a single command.

---

## ✨ Key Features

* **Live Server Inspection:** Directly connect to remote endpoints (IPv4, IPv6, domains, full URLs with or without auth/path) and extract peer certificates via TLS handshakes.
* **Certificate Chain & Intermediate CA Support:** Retrieve and extract fingerprints for the entire certificate chain (`--chain`), making resilient intermediate CA pinning effortless.
* **Local File Parsing:** Robust parsing of local `.pem`, `.crt`, or binary `.der` certificate files, with safe rejection of non-certificate binaries.
* **SPKI Extraction:** Automatically computes Subject Public Key Info (SPKI) fingerprints, recommended for resilient pinning strategies.
* **Multiple Output Formats:** Supports both standard hexadecimal (Hex) and Base64 formats (ready for Android, iOS, and OkHttp).
* **Insecure Mode for Proxies / Self-Signed:** Inspect servers with self-signed certificates or debugging proxies without TLS verification errors.
* **Robust Target Parsing:** Seamlessly accepts domain names, `host:port`, IPv6 notation (`[::1]:8443`), and browser-copied URLs (`https://user:pass@example.com:8443/api`).
* **Zero OS Dependencies:** Runs on any OS with Python, bypassing the need for native OpenSSL binaries.

---

## 📸 Demo

Testing the fingerprint extraction against a live domain:

![Domain Testing Execution](Test.png)

---

## ⚙️ Installation

**Prerequisites:** Python 3.6+ *(Note: Remote TLS `--chain` extraction requires Python 3.13+; local fullchain PEM parsing is supported on all Python versions).*

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

### 2. Full URL Parsing
Directly paste browser URLs with protocols, credentials, and paths:
```bash
python cert_detector.py -d https://api.example.com:8443/graphql
```

### 3. Extract Full Certificate Chain (Intermediate CAs)
Pinning intermediate CAs instead of leaf certificates prevents outages during frequent leaf certificate renewals.

*(Note: Extracting full remote TLS chains requires Python 3.13+; local fullchain PEM files are supported across all Python 3.6+ versions).*

```bash
python cert_detector.py -d example.com --chain
```
*Output:*
```text
[0] cert:e3b02826789...
[0] pubkey:96d43a697c...
[1] cert:948b7111af4...
[1] pubkey:cc6800e0e5...
```
*Index explanation:*
- `[0]`: Leaf (End-Entity) certificate and SPKI
- `[1]`: Intermediate CA certificate and SPKI

### 4. Base64 Format for Android / OkHttp Pinning
Mobile frameworks (Android `network_security_config.xml`, OkHttp, iOS) require Base64-encoded hashes:
```bash
python cert_detector.py -d example.com -o pubkey --format base64
```
*Output:*
```text
47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```

### 5. Remote Domain with Custom Port & Timeout
Specify a non-standard port and adjust the network timeout (in seconds):
```bash
python cert_detector.py -d myapi.example.com:8443 --timeout 10.0
```

### 6. Self-Signed Certificates & Proxy Debugging
Bypass strict TLS CA verification when testing self-signed certificates, private CAs, or proxy environments:
```bash
python cert_detector.py -d self-signed.local -k
```

### 7. IPv6 Targets
Supports IPv6 addresses with or without brackets and custom ports:
```bash
python cert_detector.py -d [::1]:8443
```

### 8. Local Certificate File Parsing
Extract fingerprints from a local `.pem`, `.crt`, or binary `.der` file:
```bash
python cert_detector.py --file ./certs/production_cert.pem
```

---

## 🧰 Command-Line Arguments

| Flag | Short | Description | Required |
| :--- | :--- | :--- | :--- |
| `--domain` | `-d` | Target domain, URL, IP (IPv4/IPv6), or host:port (e.g. `api.com:443`, `https://api.com/v1`, `[::1]:8443`). | Mutually exclusive with `--file`. |
| `--file` | `-f` | Path to a local PEM, CRT, or binary DER certificate file. | Mutually exclusive with `--domain`. |
| `--chain` | `-c` | Extract and display fingerprints for all certificates in the chain (Intermediate CAs). Requires Python 3.13+ for remote endpoints. | No |
| `--timeout` | `-t` | TLS handshake timeout in seconds (Default: `5.0`). | No |
| `--output` | `-o` | Define output mode: `cert`, `pubkey`, or `both` (Default: `both`). | No |
| `--format` | | Hash encoding format: `hex` or `base64` (Default: `hex`). | No |
| `--insecure` | `-k` | Disable TLS certificate verification (useful for self-signed certs or proxy analysis). | No |
| `--sni` | | Override TLS Server Name Indication (SNI) hostname. | No |

---

## 🛡️ Security Best Practices

When implementing pinning in production applications (e.g., iOS, Android, or IoT clients):

1.  **Prefer Public Key Pinning:** Pinning the `pubkey` prevents unexpected application outages when a CA rotates the server's certificate, provided the same Private Key is used to generate the new CSR.
2.  **Pin Intermediate CAs for Resiliency:** Pinning an intermediate CA (`--chain`) allows safe rotation of leaf certificates without requiring app updates.
3.  **Backup Pins:** Always include a backup pin (a fingerprint of a secondary key held securely offline) to ensure availability if your primary key is compromised.

---

## 📄 License

This project is open-sourced under the [MIT License](LICENSE).
