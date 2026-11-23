# Information and Network Security (202046708) — Practical Programs (Python)

Every program starts with a **docstring that gives the theory and logic in 8–10 lines**, followed by
commented code and a menu-driven interface (Encrypt / Decrypt / Exit). Only the Python standard
library is used — **nothing needs to be installed.**

**Requires:** Python 3.8 or newer (tested on 3.13). Check with `python3 --version`
(on Windows use `python` or `py`).

## Index and how to run

| No. | Practical | File | Run |
|-----|-----------|------|-----|
| 1 | Caesar cipher (+ brute-force attack) | `p01_caesar.py` | `python3 p01_caesar.py` |
| 2 | Monoalphabetic cipher | `p02_monoalphabetic.py` | `python3 p02_monoalphabetic.py` |
| 3 | Playfair cipher | `p03_playfair.py` | `python3 p03_playfair.py` |
| 4 | Polyalphabetic cipher (Vigenère + Autokey) | `p04_polyalphabetic.py` | `python3 p04_polyalphabetic.py` |
| 5 | Hill cipher (2x2, 3x3, ...) | `p05_hill.py` | `python3 p05_hill.py` |
| 6 | Rail Fence + Columnar transposition | `p06_rail_fence_columnar.py` | `python3 p06_rail_fence_columnar.py` |
| 7 | Simplified DES (S-DES) | `p07_simplified_des.py` | `python3 p07_simplified_des.py` |
| 8 | Diffie-Hellman key exchange (+ man-in-the-middle demo) | `p08_diffie_hellman.py` | `python3 p08_diffie_hellman.py` |
| 9 | RSA encryption-decryption | `p09_rsa.py` | `python3 p09_rsa.py` |
| 10 | CrypTool demonstration | `p10_cryptool_guide.md` + `p10_cryptanalysis_demo.py` | `python3 p10_cryptanalysis_demo.py` |
| 11 | Wireshark study | `p11_wireshark_guide.md` | (steps and observation table) |
| 12 | Case study: TLS 1.3 / HTTPS | `p12_case_study.md` + `p12_tls_inspect.py` | `python3 p12_tls_inspect.py www.wikipedia.org` |

`test_all.py` checks practicals 1–9 against known textbook values (`python3 test_all.py`).

## Quick test values (type these to check your run)
| Practical | Input | Expected output |
|-----------|-------|-----------------|
| 1 | `HELLO`, key 3 | `KHOOR` |
| 2 | `HELLO`, key `QWERTYUIOPASDFGHJKLZXCVBNM` | `ITSSG` |
| 3 | `Hide the gold in the tree stump`, key `playfair example` | `BMODZBXDNABEKUDMUIXMMOUVIF` |
| 4 | Vigenère `ATTACKATDAWN`, key `LEMON` | `LXFOPVEFRNHR` |
| 4 | Autokey `ATTACKATDAWN`, key `QUEENLY` | `QNXEPVYTWTWP` |
| 5 | `ACT`, key `GYBNQKURP` (3x3) | `POH` |
| 6 | Rail fence 3 rails, `WEAREDISCOVEREDFLEEATONCE` | `WECRLTEERDSOEEFEAOCAIVDEN` |
| 6 | Columnar key `ZEBRAS`, same text | `EVLNXACDTXESEAXROFOXDEECXWIREE` |
| 7 | block `01110010`, key `1010000010` | `01110111` (K1=`10100100`, K2=`01000011`) |
| 8 | menu option 3 (p=23, g=5, a=6, b=15) | A=8, B=19, shared key 2 |
| 9 | p=61, q=53, e=17, message number 65 | n=3233, d=2753, ciphertext 2790 |

## Notes
* Practicals 10, 11 and 12 are tool/study/report practicals. The `.md` files give the aim, theory, steps,
  observation tables and conclusion; **screenshots of your own CrypTool / Wireshark runs must be added by
  you**, because those tools have to be run on your computer.
* The ciphers in practicals 1–7 are classical/teaching ciphers and are **not secure** for real use.
