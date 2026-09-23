# Security Policy

## Supported Versions

OpenCipher operates as a client-side WebCrypto application. We actively maintain and patch the latest version running on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

The security and privacy of our users is paramount. If you discover a cryptographic vulnerability, side-channel attack, or implementation flaw in OpenCipher:

1. **Do not disclose the issue publicly** on GitHub issues or social media.
2. Please open a confidential security advisory or reach out via email to the project maintainers.
3. Include detailed steps to reproduce the issue (including input vectors, browser environment, and expected vs observed behavior).
4. We will acknowledge receipt of your vulnerability report within 48 hours and work with you on a patch and responsible disclosure timeline.

## Guarantees & Constraints

- OpenCipher relies on your browser's implementation of the W3C Web Cryptography API (`crypto.subtle`).
- No plaintext, derived keys, or passwords ever leave your browser memory.
- Using untrusted browser extensions may expose your DOM or clipboard; for maximum security, run OpenCipher in an incognito or clean browser profile.
