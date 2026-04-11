# PQC Readiness Scanner

**Assessing enterprise cryptographic readiness for the post-quantum era.**

Live: [pqcscanner.streamlit.app](https://pqcscanner.streamlit.app)

## What it does

The PQC Readiness Scanner evaluates any website's preparedness for post-quantum cryptography. It performs a real TLS handshake probe to detect whether a site supports quantum-resistant key exchange (X25519MLKEM768), and provides a dual-score assessment: classical security grade vs. PQC readiness grade.

## Key capabilities

- **Dual scoring**: Classical TLS Security (A+ to F) and PQC Readiness (A+ to F) as independent grades
- **Real PQC detection**: OpenSSL TLS handshake probing for X25519MLKEM768 hybrid key exchange
- **CDN-aware**: Distinguishes between organizational PQC deployment and CDN-provided PQC (Cloudflare, AWS CloudFront)
- **CAC40 leaderboard**: Daily automated assessment of France's top 40 companies
- **HNDL risk assessment**: "Harvest Now, Decrypt Later" risk analysis by sector with data lifetime estimates
- **Cloud migration guides**: PQC enablement steps for AWS, Azure, GCP, and Cloudflare
- **Bilingual** French/English interface

## How scoring works

Two independent scores reveal the gap between current security and quantum readiness:

| Component | Classical Score | PQC Score |
|-----------|:-:|:-:|
| TLS version (1.3 vs 1.2) | +30 | +10 |
| Key exchange (X25519, MLKEM) | +15 | +40 |
| Symmetric cipher (AES-256-GCM) | +20 | +15 |
| Certificate signature (RSA/ECDSA) | +15 | +5 |
| Hash function (SHA-256/384) | +10 | +5 |
| PQC hybrid (X25519MLKEM768) | +10 | +25 |

A site can score **A in classical security but F in PQC readiness**. That gap is the "Harvest Now, Decrypt Later" risk.

## Architecture

- **Frontend**: Streamlit (scanner + leaderboard + HNDL risk assessment + cloud guides)
- **Detection**: OpenSSL 3.5+ TLS handshake probing with PQC group negotiation
- **CDN detection**: Certificate issuer + HTTP header analysis (Cloudflare, AWS, Fastly, Akamai)
- **Automation**: GitHub Actions daily CAC40 scan at 6:00 UTC
- **Retry logic**: 3x probes per PQC group to handle CDN edge server rotation

## Related

- [DomainWatch](https://domainwatch.streamlit.app) -- Enterprise brand protection against domain impersonation attacks

## Author

[Amin Hasbini](https://www.linkedin.com/in/amin-hasbini-cybersecurity/) -- AI & Cybersecurity Strategy Executive
