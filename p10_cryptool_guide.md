# Practical 10 — Demonstrate and perform various encryption-decryption techniques with CrypTool

**Companion program:** `p10_cryptanalysis_demo.py` repeats the same experiments in Python
(run `python3 p10_cryptanalysis_demo.py`) so you can compare the results with CrypTool.

## 1. Aim
To use the open-source tool **CrypTool** to encrypt, decrypt and analyse classical and modern
ciphers.

## 2. Theory (about 10 lines)
CrypTool is a free e-learning program (University of Kassel / Deutsche Bank, now an open-source
project) that visualises cryptographic algorithms. It has several editions:
CrypTool 1 (CT1, Windows desktop, classic menu `Encrypt/Decrypt`, `Analysis`),
CrypTool 2 (CT2, Windows, drag-and-drop workflow of components), JCrypTool (Java, all platforms)
and CrypTool-Online (in the browser, https://www.cryptool.org/en/cto/). It covers
classical ciphers (Caesar, Vigenere, Playfair, Hill, transposition), symmetric ciphers (DES, AES,
RC4), asymmetric methods (RSA, Diffie-Hellman), hash functions (MD5, SHA) and cryptanalysis
(frequency analysis, brute force, Kasiski test, index of coincidence). Encryption turns plaintext
into ciphertext with a key; decryption reverses it; cryptanalysis tries to recover the plaintext
without the key.

## 3. Requirements
* CrypTool 1 / CrypTool 2 / JCrypTool from https://www.cryptool.org/en/ (download page), **or**
  just a browser with CrypTool-Online (no installation).
* A sample text file, e.g. the paragraph used in `p10_cryptanalysis_demo.py` (`SAMPLE`).

## 4. Steps to perform

### A. Classical encryption and decryption (CrypTool 1)
1. Start CrypTool and open a new document; type or paste the plaintext
   `ATTACK THE EASTERN GATE AT DAWN`.
2. Menu **Encrypt/Decrypt → Symmetric (classic) → Caesar / Rot-X…**, set key `5`, press **Encrypt**.
   A new window shows the ciphertext. Compare with `p01_caesar.py`.
3. Repeat with **Vigenère…** (key `LEMON`), **Playfair…** (key `PLAYFAIR EXAMPLE`), **Hill…**
   (2x2 or 3x3 key) and **Substitution…** (monoalphabetic), **Permutation / Transposition…**
   (columnar / rail fence). Note each ciphertext in the table of section 5.
4. Use **Decrypt** with the same key to prove the original plaintext returns.

### B. Modern symmetric encryption
1. Menu **Encrypt/Decrypt → Symmetric (modern) → AES (Rijndael)…** (or **DES**).
2. Enter a hexadecimal key (e.g. 16 bytes for AES-128), press **Encrypt**, then **Decrypt**.
3. Observe that the same plaintext gives completely different output for a different key, and
   that the ciphertext looks random (compare with the classical result).

### C. Asymmetric encryption (RSA)
1. Menu **Indiv. Procedures → RSA Cryptosystem → RSA Demonstration** (CT1).
2. Choose two primes `p`, `q` (e.g. 61 and 53), `e = 17`; CrypTool shows `n`, `phi(n)` and `d`.
3. Encrypt a number or text with the public key, decrypt with the private key. Compare with
   `p09_rsa.py` (n = 3233, d = 2753).

### D. Cryptanalysis
1. Encrypt a long English text with Caesar (key 11), then use
   **Analysis → Symmetric Encryption (classic) → Ciphertext only → Caesar** – CrypTool shows
   the recovered key.
2. Open **Analysis → Tools for Analysis → Histogram** (or *N-Gram*) to see letter frequencies.
3. Encrypt the text with Vigenère (key `CIPHER`) and use **Analysis → Symmetric Encryption
   (classic) → Ciphertext only → Vigenère**; CrypTool finds the key length (Kasiski / IC /
   autocorrelation) and the key.

### E. Hash functions (optional)
**Indiv. Procedures → Hash → Hash Demonstration**: change one letter of the input and observe the
avalanche effect in MD5 / SHA-1 / SHA-256.

*(In CrypTool 2 the same experiments are built by dragging the components "Text Input →
Caesar / Vigenère / AES → Text Output" onto the workspace and pressing Play.)*

## 5. Observation table (fill in from your own run)
| Cipher | Key | Plaintext | Ciphertext (CrypTool) | Same as my Python program? |
|--------|-----|-----------|-----------------------|----------------------------|
| Caesar | 5 | ATTACK THE EASTERN GATE AT DAWN | | |
| Vigenère | LEMON | same | | |
| Playfair | PLAYFAIR EXAMPLE | same | | |
| Hill | GYBNQKURP | same | | |
| Rail fence | 3 rails | same | | |
| AES | (hex key) | same | | |
| RSA | e=17, n=3233 | 65 | | |

Expected for the Python programs (`p10_cryptanalysis_demo.py`): Caesar `FYYFHP YMJ JFXYJWS LFYJ FY IFBS`,
Vigenère `LXFOPV XTS RLWFSEY KMHR LX POJY`.

## 6. Conclusion (sample wording)
CrypTool made it possible to encrypt and decrypt with classical, symmetric and asymmetric
algorithms and to attack weak ciphers. Caesar and Vigenère were broken automatically (brute force and
index-of-coincidence analysis), showing why they are insecure, whereas AES and RSA could not be
attacked without the key.

> Note: screenshots of your own CrypTool windows should be added to the journal — they cannot be
> generated here because the tool has to be run on your computer.
