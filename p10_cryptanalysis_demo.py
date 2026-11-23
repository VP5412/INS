"""
====================================================================
Practical No : 10 (program part)
Title        : Demonstrate and perform various encryption-decryption
               techniques - companion to the CryptTool exercise.
====================================================================
THEORY & LOGIC
 1. CrypTool (see p10_cryptool_guide.md) is used to ENCRYPT, DECRYPT
    and ATTACK classical ciphers. This program repeats the same three
    experiments in Python so the results can be compared.
 2. Demo 1 - encryption: the same plaintext is encrypted with Caesar,
    Vigenere, Rail fence and Hill and the results are displayed side
    by side (the code of Practicals 1, 4, 5 and 6 is re-used).
 3. Demo 2 - frequency analysis: the letters of a ciphertext are
    counted. In a monoalphabetic cipher the most frequent cipher
    letter usually stands for E (English: E, T, A, O, I, N).
 4. Demo 3 - Caesar attack: all 26 shifts are tried and each result is
    scored with a chi-squared test against English letter
    frequencies; the lowest score is the most English-like text.
 5. Demo 4 - Vigenere attack: the key length m is estimated with the
    INDEX OF COINCIDENCE (IC = sum n_i(n_i-1) / N(N-1)).
    English has IC about 0.066, random text about 0.038.
 6. For the right key length every m-th letter was shifted by the SAME
    key letter, so each column is a Caesar cipher and is solved with
    the chi-squared test of Demo 3.
 7. The recovered key letters give the complete key and the plaintext
    (a long ciphertext, 200+ letters, is needed to work reliably).
 8. Lesson: the weak points of every cipher on this list are exactly
    what CrypTool's analysis menu shows - small key space (Caesar),
    surviving letter frequencies (monoalphabetic), repeating key
    (Vigenere).
 9. Usage:  python3 p10_cryptanalysis_demo.py

Run : python3 p10_cryptanalysis_demo.py
====================================================================
"""
from collections import Counter

import p01_caesar as caesar
import p04_polyalphabetic as vig
import p05_hill as hill
import p06_rail_fence_columnar as rail

# relative frequency (%) of the letters A..Z in English text
ENGLISH = [8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77,
           4.03, 2.41, 6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98,
           2.36, 0.15, 1.97, 0.07]

SAMPLE = ("Cryptography is the practice and study of techniques for secure "
          "communication in the presence of adversaries. Modern cryptography "
          "exists at the intersection of mathematics, computer science and "
          "electrical engineering. Applications of cryptography include "
          "electronic commerce, chip based payment cards, digital currencies, "
          "computer passwords and military communications. Before the modern "
          "era cryptography was concerned with message confidentiality, the "
          "conversion of messages from a comprehensible form into an "
          "incomprehensible one and back again at the other end, rendering it "
          "unreadable by interceptors or eavesdroppers without secret "
          "knowledge, namely the key used to encrypt and decrypt the message.")


def letters(text):
    return [c for c in text.upper() if "A" <= c <= "Z"]


def chi_squared(text):
    """Lower value = more like English."""
    ls = letters(text)
    n = len(ls) or 1
    counts = Counter(ls)
    return sum((counts.get(chr(65 + i), 0) - n * ENGLISH[i] / 100) ** 2
               / (n * ENGLISH[i] / 100) for i in range(26))


def index_of_coincidence(seq):
    n = len(seq)
    if n < 2:
        return 0.0
    return sum(c * (c - 1) for c in Counter(seq).values()) / (n * (n - 1))


def break_caesar(cipher):
    best = min(range(26), key=lambda k: chi_squared(caesar.caesar(cipher, k, True)))
    return best, caesar.caesar(cipher, best, True)


def vigenere_key_length(cipher, max_len=12):
    """Smallest length whose columns look English (IC close to 0.066)."""
    ls = letters(cipher)
    scores = {}
    for m in range(1, max_len + 1):
        cols = [ls[i::m] for i in range(m)]
        scores[m] = sum(index_of_coincidence(c) for c in cols) / m
    best = max(scores.values())
    for m in range(1, max_len + 1):          # prefer the shortest good length
        if scores[m] >= best - 0.008:
            return m, scores
    return 1, scores


def break_vigenere(cipher):
    m, scores = vigenere_key_length(cipher)
    ls = "".join(letters(cipher))
    key = ""
    for i in range(m):
        column = ls[i::m]
        shift, _ = break_caesar(column)
        key += chr(65 + shift)
    return key, m, vig.vigenere(cipher, key, decrypt=True)


def demo_encrypt():
    plain = "ATTACK THE EASTERN GATE AT DAWN"
    print("Plaintext      :", plain)
    print("Caesar (k=5)   :", caesar.caesar(plain, 5))
    print("Vigenere LEMON :", vig.vigenere(plain, "LEMON"))
    print("Autokey QUEEN  :", vig.autokey(plain, "QUEEN"))
    print("Hill GYBNQKURP :", hill.encrypt(plain, hill.key_matrix("GYBNQKURP")))
    print("Rail fence (3) :", rail.rail_encrypt(plain.replace(" ", ""), 3))
    print("Columnar ZEBRAS:", rail.columnar_encrypt(plain, "ZEBRAS"))


def demo_frequency():
    cipher = caesar.caesar(SAMPLE, 7)
    counts = Counter(letters(cipher))
    total = sum(counts.values())
    print("Letter frequencies of a Caesar-encrypted text (top 6):")
    for ch, n in counts.most_common(6):
        print(f"  {ch}: {n:3d}  ({100 * n / total:4.1f} %)  " + "#" * (n * 40 // total))
    top = counts.most_common(1)[0][0]
    print(f"Most frequent cipher letter is {top}; if it stands for E the shift is "
          f"{(ord(top) - ord('E')) % 26}.")


def main():
    print("=" * 60, "\nDEMO 1 - encrypt one message with several ciphers\n" + "=" * 60)
    demo_encrypt()

    print("\n" + "=" * 60, "\nDEMO 2 - frequency analysis\n" + "=" * 60)
    demo_frequency()

    print("\n" + "=" * 60, "\nDEMO 3 - break a Caesar cipher (no key known)\n" + "=" * 60)
    cipher = caesar.caesar(SAMPLE, 11)
    key, plain = break_caesar(cipher)
    print("Ciphertext :", cipher[:60], "...")
    print(f"Recovered key = {key}")
    print("Plaintext  :", plain[:60], "...")

    print("\n" + "=" * 60, "\nDEMO 4 - break a Vigenere cipher (no key known)\n" + "=" * 60)
    secret = "CIPHER"
    cipher = vig.vigenere(SAMPLE, secret)
    print("Ciphertext :", cipher[:60], "...")
    key, m, plain = break_vigenere(cipher)
    print(f"Estimated key length = {m}  (true key length {len(secret)})")
    print(f"Recovered key        = {key}  (true key {secret})")
    print("Plaintext  :", plain[:60], "...")


if __name__ == "__main__":
    main()
