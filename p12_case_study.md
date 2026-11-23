# Practical 12 — Detailed case study: Real-world implementation of a network security algorithm / concept

# Case Study: Securing the Web with TLS 1.3 (HTTPS)

**Course:** Information and Network Security (202046708)   **Companion program:** `p12_tls_inspect.py`

---

## 1. Introduction
Every time a browser shows a padlock, the connection is protected by **TLS (Transport Layer
Security)**, the successor of SSL. HTTPS is simply HTTP carried inside a TLS connection (port 443).
TLS is the most widely deployed network-security protocol in the world: it protects online banking,
e-mail, shopping, messaging apps and APIs. This case study explains how TLS 1.3 (RFC 8446, 2018) uses
the algorithms studied in this course to give three guarantees.

| Security goal | Mechanism in TLS |
|---------------|------------------|
| **Confidentiality** | symmetric encryption (AES-GCM / ChaCha20) with keys from a Diffie-Hellman exchange |
| **Integrity** | AEAD authentication tag (GCM / Poly1305); handshake hashed with SHA-256/384 |
| **Authentication** | X.509 certificates, digital signatures (RSA / ECDSA), chain of trust to a CA |

## 2. Problem Statement
HTTP sends everything in clear text. Anyone on the path (Wi-Fi owner, ISP, attacker) can
*read* passwords (eavesdropping), *change* pages (tampering) or *impersonate* a site
(man-in-the-middle). Wireshark (Practical 11) shows this clearly. The aim is to protect
communication between two parties who have **never met and share no secret**.

## 3. Where TLS fits
```
Application layer   HTTP, SMTP, IMAP, FTP, ...
        |
Security layer      TLS  (Record protocol + Handshake protocol)   <-- this case study
        |
Transport layer     TCP (port 443 for HTTPS)
        |
Network / Link      IP / Ethernet / Wi-Fi
```
* **Handshake protocol** – negotiates version and cipher suite, authenticates the server, creates keys.
* **Record protocol** – splits data in records, encrypts and authenticates each one.
* **Alert protocol** – reports errors (bad certificate, handshake failure) and closes the session.

## 4. Algorithms used and the course topics they match
| Step | Algorithm (typical) | Course unit |
|------|---------------------|-------------|
| Key exchange | **ECDHE** (X25519 / secp256r1) – elliptic-curve Diffie-Hellman, new key per session | Unit 3 – Diffie-Hellman (Practical 8) |
| Server authentication | X.509 certificate signed with **RSA** or **ECDSA** | Unit 3 / 5 – RSA, digital signature (Practical 9) |
| Bulk encryption | **AES-128/256-GCM**, **ChaCha20-Poly1305** | Unit 2 – AES, block cipher modes |
| Hash / PRF | **SHA-256 / SHA-384**, **HKDF** key derivation | Unit 4 – hash functions, MAC |
| Message authentication | GCM / Poly1305 tags (AEAD), formerly HMAC | Unit 4 – MAC, HMAC |
| Trust | Certificate Authorities, certificate chain, revocation (OCSP) | Unit 5 – remote user authentication |

A TLS 1.3 *cipher suite* names only the symmetric part, e.g. `TLS_AES_256_GCM_SHA384`
= AES-256 in GCM mode with SHA-384 for key derivation. (`p12_tls_inspect.py` prints this name.)

## 5. TLS 1.3 handshake (1-RTT) step by step
```
Client                                                   Server
  | -- ClientHello ------------------------------------>  |  versions, cipher suites,
  |    (random, supported groups, key_share = g^a)        |  SNI (host name), key share
  | <------------------------------------ ServerHello --  |  chosen suite, key_share = g^b
  |        === from here on everything is ENCRYPTED ===   |
  | <------------------- EncryptedExtensions, Certificate, |  server's X.509 certificate
  | <---------------------------- CertificateVerify -----  |  signature over handshake hash
  | <--------------------------------------- Finished --  |  MAC over whole handshake
  | -- Finished ---------------------------------------->  |
  | <=============== Application Data (AES-GCM) =========>  |
```
1. **ClientHello** – the client lists the cipher suites it supports and already sends its
   Diffie-Hellman public value `g^a` (this is why TLS 1.3 needs only one round trip).
2. **ServerHello** – the server picks a suite and sends `g^b`. Both sides compute the shared
   secret `g^(ab)` and derive handshake and traffic keys with HKDF. No key is ever sent.
3. **Certificate + CertificateVerify** – the server sends its certificate and *signs* the
   handshake transcript with its private key, proving it owns the certificate (prevents
   man-in-the-middle, the weakness of plain Diffie-Hellman shown in Practical 8).
4. **Finished** – each side sends a MAC over the entire handshake; a changed message (e.g. a
   downgrade attempt) makes verification fail.
5. **Application data** is encrypted with AES-GCM using fresh per-direction keys.

**Forward secrecy:** because a new ephemeral DH key is created for every session and then
discarded, stealing the server's long-term private key later cannot decrypt recorded old traffic.

## 6. How a browser trusts a certificate
1. The server sends its certificate (subject = domain name, public key, validity, issuer, signature).
2. The browser builds the chain *server cert → intermediate CA → root CA* and checks each digital
   signature using the issuer's public key.
3. The root must be in the operating-system / browser **trust store**.
4. It checks the validity dates, that the domain name matches (SAN) and that the certificate has not been
   revoked (OCSP / CRL / CRLite).
If any check fails the browser shows a warning (`p12_tls_inspect.py` reports it as
*CERTIFICATE VERIFICATION FAILED*).

## 7. Real-world implementation
* **Libraries:** OpenSSL, BoringSSL (Chrome/Android), LibreSSL, Schannel (Windows), Secure Transport
  (Apple), GnuTLS, Python `ssl`.
* **Servers:** Nginx / Apache / IIS are configured with a certificate and a list of allowed protocols and
  cipher suites, e.g. in Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`
* **Certificates:** free automated certificates from Let's Encrypt (ACME protocol), 90-day lifetime.
* **HSTS** header forces browsers to use HTTPS only; **certificate transparency** logs expose mis-issued
  certificates.
* **Where else TLS is used:** SMTP/IMAP over TLS, VPNs (OpenVPN), MQTT for IoT, database
  connections, and QUIC / HTTP-3 (TLS 1.3 built into the transport protocol).

### Demonstration with the companion program
```
python3 p12_tls_inspect.py www.wikipedia.org
```
Shows the negotiated version (TLSv1.3), cipher suite, key length, certificate owner, issuer, validity
period and the alternative names. Capture the same connection with Wireshark (filter `tls.handshake`) and
match the ClientHello / ServerHello fields with this output.
(Tested offline against a local server: TLSv1.3, `TLS_AES_256_GCM_SHA384`, 256 bit.)

## 8. Known attacks and the lesson learned
| Attack | Year | Cause | Fix |
|--------|------|-------|-----|
| **BEAST** | 2011 | predictable IV in CBC mode (SSL 3.0 / TLS 1.0) | TLS 1.1+, 1/n-1 record splitting |
| **CRIME / BREACH** | 2012/13 | compression leaks secret length | disable TLS compression, mask tokens |
| **Heartbleed** | 2014 | OpenSSL bug (buffer over-read) leaked memory, even private keys | patch, revoke and re-issue certificates |
| **POODLE** | 2014 | SSL 3.0 padding oracle; protocol downgrade | disable SSL 3.0 |
| **FREAK / Logjam** | 2015 | weak "export-grade" RSA / DH parameters | remove export suites, use 2048-bit+ |
| **Sweet32** | 2016 | 64-bit block ciphers (3DES) – birthday attack | remove 3DES |
| **ROBOT** | 2017 | RSA key-exchange padding oracle | prefer ECDHE; TLS 1.3 removes RSA key transport |

TLS 1.3 deliberately **removed** old, weak features: RSA key exchange, static DH, CBC and RC4 ciphers,
MD5/SHA-1, compression and renegotiation. Only AEAD ciphers and ephemeral key exchange remain.

## 9. TLS 1.2 vs TLS 1.3
| Feature | TLS 1.2 | TLS 1.3 |
|---------|---------|---------|
| Handshake round trips | 2-RTT | 1-RTT (0-RTT resumption possible) |
| Key exchange | RSA or (EC)DHE | only (EC)DHE – forward secrecy always |
| Cipher modes | CBC, RC4, GCM | only AEAD (GCM, ChaCha20-Poly1305) |
| Certificate visible to eavesdropper | yes | no (encrypted) |
| Cipher suites | > 300 | 5 |

## 10. Conclusion
TLS shows how the individual techniques of this course are combined in practice: Diffie-Hellman
agrees on a key, digital signatures and certificates authenticate the server, hash functions and MACs
guarantee integrity, and AES encrypts the data. History (BEAST to ROBOT) also shows that security
is not static — weak algorithms and bad implementations must be replaced, which is what TLS 1.3 did.

## 11. References
1. William Stallings, *Cryptography and Network Security: Principles and Practice*, Pearson – chapters on
   Transport-Level Security (SSL/TLS), HTTPS, SSH.
2. E. Rescorla, **RFC 8446** – *The Transport Layer Security (TLS) Protocol Version 1.3*, IETF, 2018.
3. Cloudflare Learning Center – "What is TLS?"; Mozilla *Server Side TLS* guidelines.
4. Course PDF reference list (Kahate, Forouzan, Stamp, Harini et al.).

---
*Alternative topics if your faculty prefers another case study:* SSH key authentication, WhatsApp
end-to-end encryption (Signal protocol), WPA3 Wi-Fi security, Kerberos in Windows Active Directory, PGP
e-mail encryption, or the RSA SecurID / Bitcoin digital-signature system.
