# SIGrypt

### This software uses zero libraries!

SIGrypt is an end-to-end encrypted and LoRa-based communication software. Operates on quantum resistant cryptography such as AES-256, SHA-384, and HMAC-SHA384. Designed to be a PSK model and P2P.

---
🇺🇸 **CONFIGURED FOR USE IN THE UNITED STATES** 🇺🇸
---

## Requirements

- x86-64 Linux System
- CPU with AES-NI
- Reyax RYLR998 LoRa Module
- USB to TTL Serial Converter
  
---
![LoRa SDR View](images/LoRa_Freqs.webp)

---

## Build

![Build Demo](demo/build.gif)

[!] For help with wiring the module to the TTL check images/connections.webp

---

## Dependency-Free

This repository uses zero libraries for **portability**, **transparency**, and **attack surface reduction**.

---

## Cryptography

- Native AES-256-CTR  : Passed official NIST SP 800-38A CTR and IETF RFC3686 CTR official test vectors
- Native SHA-384      : Passed official NIST test vectors (SHA384ShortMsg.rsp, SHA384LongMsg.rsp, SHA384Monte.rsp)
- Native HMAC-SHA384  : Passed official NIST test vectors (HMAC.rsp)

---

## Replay Protection

Anti-replay techniques are employed such as:

- **Duplicate ID Caching**: caching 3 most recent message IDs (Rejects payload if ID is already cached)
- **Time-sensitive Validation**: Rejecting old payloads (Payload Age > 30 seconds)
- **Cryptographically Binded**: timestamp of payload is cryptographically binded using native HMAC-SHA384

---

## Regulatory / legality (US-only configuration)

- This project is **configured for the US 902–928 MHz ISM band**.
- It is **not intended for use in other countries/regions**.
- **You are responsible for legal operation and compliance** with FCC rules (frequency use, transmit power, antenna, hopping/dwell time, duty cycle, and any required labeling/testing for your finished device).  
- **FCC-certified modules do not automatically make your full build/product compliant.**
- This software is provided **as-is** with no warranty of regulatory compliance.
