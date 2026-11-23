"""
====================================================================
Practical No : 12 (program part)
Title        : Real-world implementation of a network security
               algorithm - inspect a live TLS (HTTPS) connection.
====================================================================
THEORY & LOGIC
 1. TLS (Transport Layer Security) is the protocol behind HTTPS. It
    combines every concept of this subject: asymmetric cryptography
    (key exchange, certificates), symmetric ciphers (AES), hash
    functions / MACs (SHA-2, HMAC) and digital signatures.
 2. In the handshake the client and server agree on a protocol
    version and a CIPHER SUITE, the server proves its identity with
    an X.509 certificate, and both derive shared session keys by an
    (EC)DHE key exchange (Practical 8).
 3. The certificate is signed by a Certificate Authority (CA); the
    client checks the signature chain, the validity dates and that
    the host name matches the certificate (digital signature, RSA/ECDSA).
 4. After the handshake all data is protected with a symmetric AEAD
    cipher such as AES-GCM or ChaCha20-Poly1305 (confidentiality +
    integrity).
 5. This program uses Python's built-in ssl module: it opens a TCP
    socket, performs the real handshake and then prints what was
    negotiated.
 6. Printed information: TLS version, cipher suite name, key length in
    bits, certificate subject, issuer, validity period, days left and
    the alternative host names (SAN).
 7. Certificate verification is ON by default (CERT_REQUIRED +
    hostname check); a failure is reported instead of being ignored.
 8. Option --insecure turns verification off (testing only - this
    makes the connection open to a man-in-the-middle attack);
    --cafile lets you trust a private/self-signed CA.
 9. Compare the output with the Client Hello / Server Hello packets
    captured in Wireshark (Practical 11).

Run : python3 p12_tls_inspect.py www.wikipedia.org
      python3 p12_tls_inspect.py localhost 8443 --cafile cert.pem
====================================================================
"""
import socket
import ssl
import sys
import time


def name_to_text(rdn_sequence):
    """Turn the ssl module's nested subject/issuer tuples into text."""
    return ", ".join(f"{k}={v}" for rdn in rdn_sequence for (k, v) in rdn)


def inspect(host, port=443, cafile=None, insecure=False, timeout=10):
    context = ssl.create_default_context(cafile=cafile)
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cipher_name, _, bits = tls.cipher()
            return {
                "host": host,
                "port": port,
                "version": tls.version(),
                "cipher": cipher_name,
                "bits": bits,
                "cert": tls.getpeercert(),          # {} when verification is off
                "verified": not insecure,
            }


def report(info):
    print(f"Server          : {info['host']}:{info['port']}")
    print(f"TLS version     : {info['version']}")
    print(f"Cipher suite    : {info['cipher']}")
    print(f"Key length      : {info['bits']} bits")
    print(f"Verified by CA  : {'yes' if info['verified'] else 'NO (insecure mode)'}")
    cert = info["cert"]
    if not cert:
        print("Certificate     : details not available (verification disabled)")
        return
    print(f"Subject         : {name_to_text(cert['subject'])}")
    print(f"Issuer          : {name_to_text(cert['issuer'])}")
    print(f"Valid from      : {cert['notBefore']}")
    print(f"Valid until     : {cert['notAfter']}")
    days = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
    print(f"Days remaining  : {days:.0f}")
    sans = [v for (k, v) in cert.get("subjectAltName", ()) if k == "DNS"]
    if sans:
        print(f"Alt. host names : {', '.join(sans[:8])}{' ...' if len(sans) > 8 else ''}")
    print(f"Serial number   : {cert.get('serialNumber')}")


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    insecure = "--insecure" in argv
    cafile = None
    if "--cafile" in argv:
        i = argv.index("--cafile")
        if i + 1 >= len(argv):
            print("--cafile needs a file name")
            return 2
        cafile = argv[i + 1]
        args = [a for a in args if a != cafile]
    if not args:
        print("Usage: python3 p12_tls_inspect.py HOST [PORT] [--cafile FILE] [--insecure]")
        print("   e.g. python3 p12_tls_inspect.py www.wikipedia.org")
        return 2
    host = args[0]
    port = int(args[1]) if len(args) > 1 else 443
    try:
        report(inspect(host, port, cafile, insecure))
    except ssl.SSLCertVerificationError as err:
        print("CERTIFICATE VERIFICATION FAILED:", err.verify_message)
        return 1
    except (ssl.SSLError, OSError) as err:
        print("Connection error:", err)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
