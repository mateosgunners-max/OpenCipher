<p align="center">
  <img src="https://img.shields.io/badge/OpenCipher-v1.0-00F0FF?style=for-the-badge&logo=shield" alt="OpenCipher Logo">
</p>

<h1 align="center">OpenCipher</h1>

<p align="center">
  <strong>Zero-Knowledge, Client-Side Cryptographic & Privacy Workbench</strong><br>
  <em>100% Offline. Zero Telemetry. Zero Servers. Powered by the W3C Web Cryptography API.</em>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-10B981?style=flat-square" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/Dependencies-ZERO-00F0FF?style=flat-square" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/Telemetry-NONE-10B981?style=flat-square" alt="Zero Telemetry">
  <img src="https://img.shields.io/badge/API-W3C_WebCrypto-8B5CF6?style=flat-square" alt="WebCrypto API">
  <img src="https://img.shields.io/badge/PRs-Welcome-F59E0B?style=flat-square" alt="PRs Welcome">
</p>

---

## 🛡️ Why OpenCipher?

Every day, software engineers, security analysts, journalists, and privacy advocates use online tools to encrypt strings, inspect JWT tokens, test RSA keys, and calculate checksums. 

**The hidden danger:** Most online "crypto calculators" or "JWT debuggers" send your sensitive data, private keys, or passwords to cloud servers, logging them in plaintext analytics, server logs, or caching proxies.

**OpenCipher eliminates this risk entirely.** It is built exclusively on the native browser **W3C Web Cryptography API** (`window.crypto.subtle` and `crypto.getRandomValues`). 
- **No data ever leaves your device.**
- **No tracking scripts, cookies, or remote analytics.**
- **Works completely air-gapped / offline.**
- **Zero npm dependencies** — zero risk of supply-chain attacks.

---

## ⚡ Core Cryptographic Capabilities

### 1. 🔐 Authenticated AES-GCM 256-Bit Vault
* **KDF:** PBKDF2 with SHA-256 and 100,000 iterations to derive a 256-bit AES key from your passphrase.
* **Initialization Vector (IV):** Cryptographically secure 96-bit (12-byte) IV generated per operation via CSPRNG.
* **Authentication Tag:** Authenticated Galois/Counter Mode (GCM) guarantees that any tampering or incorrect password causes immediate authentication failure.
* **File Encryption:** Encrypt any local binary file (PDF, archive, photo) up to 100MB in-memory and download a `.opencipher` container.

### 2. 🔑 RSA Key Studio (2048 / 4096-bit)
* Generates hardware-entropy RSA-OAEP asymmetric keypairs.
* Exports standard PEM files (`-----BEGIN PUBLIC KEY-----` and `-----BEGIN PRIVATE KEY-----`).
* Built-in live encryption/decryption sandbox to verify keypair integrity before deployment.

### 3. ⚡ Multi-Algorithm Hash & Integrity Engine
* Computes cryptographic digests concurrently in real-time as you type:
  * **SHA-256**
  * **SHA-512**
  * **SHA-384**
  * **SHA-1** (flagged as legacy)
* **Integrity Comparator:** Match computed hash against known release checksums with instant visual confirmation.

### 4. 📜 Offline JWT (JSON Web Token) Inspector & Verifier
* Decodes Header and Payload claims with human-readable timestamp evaluation (`exp`, `iat`, `nbf`).
* **Offline HMAC Verification:** Verify HS256 signatures locally by providing your secret key — without sharing your secret with any remote server.

### 5. 🎲 CSPRNG Diceware Passphrase & Entropy Auditor
* True cryptographic randomness via `window.crypto.getRandomValues`.
* Diceware wordlist passphrases (e.g. `zenith-cascade-neutron-vanguard`).
* Mathematical Shannon entropy calculator & NIST SP 800-63B brute-force resistance estimator.

### 6. 🔄 Format Converter
* Safe client-side translation between Base64, Hexadecimal, and URL-encoding formats.

### 7. 🚨 Panic / Memory Zeroize Protocol
* Instant one-click purge: wipes all memory buffers, input fields, active keys, and overwrites the system clipboard.

---

## 🔒 Threat Model & Cryptographic Guarantees

| Primitive | Standard | Parameters |
| :--- | :--- | :--- |
| **Symmetric Cipher** | AES-GCM | 256-bit key, 96-bit CSPRNG IV, 128-bit Auth Tag |
| **Key Derivation** | PBKDF2 | SHA-256, 100,000 rounds, 128-bit random salt |
| **Asymmetric Cipher** | RSA-OAEP | 2048 / 4096-bit modulus, SHA-256 digest |
| **Digital Signatures** | HMAC-SHA256 | Strict byte-constant evaluation |
| **Random Number Gen** | CSPRNG | Native OS entropy pool via `crypto.getRandomValues` |

---

## 🚀 Quick Start (Run Locally in 5 Seconds)

Because OpenCipher has **zero build steps and zero dependencies**, you can run it immediately with any local server:

### Using Python 3:
```bash
git clone https://github.com/mateosgunners-max/Aura-Crest.git opencipher
cd opencipher
python3 -m http.server 8080
```
Open `http://localhost:8080` in your browser.

### Using Node.js:
```bash
npx serve .
```

---

## 🌐 Browser Compatibility

OpenCipher runs on any modern browser that supports the W3C Web Cryptography API:
- Google Chrome 37+
- Mozilla Firefox 34+
- Apple Safari 11+
- Microsoft Edge 79+
- Android Browser & Mobile Safari

---

## 🤝 Contributing

Contributions are warmly welcomed! Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md) before submitting a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/NewCipher`)
3. Commit your Changes (`git commit -m 'Add post-quantum lattice primitive'`)
4. Push to the Branch (`git push origin feature/NewCipher`)
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.
