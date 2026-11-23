"""
====================================================================
Practical No : 2
Title        : To implement Monoalphabetic cipher encryption-decryption.
====================================================================
THEORY & LOGIC
 1. A monoalphabetic cipher replaces each plaintext letter by ONE fixed
    cipher letter; the same plaintext letter always gives the same
    ciphertext letter (a single substitution alphabet).
 2. The key is a permutation of the 26 letters: the i-th letter of the
    key is the replacement of the i-th letter of the alphabet.
        plain : A B C D E F G H ...
        key   : Q W E R T Y U I ...   (A->Q, B->W, C->E ...)
 3. There are 26! (about 4 x 10^26) possible keys, so brute force is
    impossible; the Caesar cipher is the special case of a shifted key.
 4. A key can be made easily from a KEYWORD: write the keyword without
    repeated letters, then the unused letters of the alphabet.
 5. Encryption : look up each letter in the table plain -> key.
    Decryption : use the INVERSE table (key -> plain).
 6. The program validates that the key has exactly 26 different
    letters, otherwise decryption would not be unique.
 7. Case of the letters is preserved; non-letters are left unchanged.
 8. Weakness: the letter frequencies of the language survive (E, T, A
    are still the most common), so frequency analysis breaks it.
 9. Example: key QWERTYUIOPASDFGHJKLZXCVBNM, HELLO -> ITSSG.

Run : python3 p02_monoalphabetic.py
====================================================================
"""
import random
import string

ALPHABET = string.ascii_uppercase


def valid_key(key):
    """A valid key has 26 letters and uses every letter exactly once."""
    return len(key) == 26 and set(key.upper()) == set(ALPHABET)


def key_from_keyword(keyword):
    """Keyword (without repeats) followed by the unused letters."""
    seen = []
    for ch in keyword.upper() + ALPHABET:
        if ch in ALPHABET and ch not in seen:
            seen.append(ch)
    return "".join(seen)


def random_key():
    letters = list(ALPHABET)
    random.shuffle(letters)
    return "".join(letters)


def substitute(text, table):
    """Replace letters using table (dict of upper-case letters)."""
    out = []
    for ch in text:
        if ch.upper() in table and ch.isascii():
            new = table[ch.upper()]
            out.append(new if ch.isupper() else new.lower())
        else:
            out.append(ch)
    return "".join(out)


def encrypt(text, key):
    return substitute(text, dict(zip(ALPHABET, key.upper())))


def decrypt(text, key):
    return substitute(text, dict(zip(key.upper(), ALPHABET)))   # inverse


def get_key():
    print("Key options:  1) type a 26-letter key   2) from a keyword   3) random")
    opt = input("Option: ").strip()
    if opt == "1":
        key = input("26-letter key: ").strip().upper()
    elif opt == "2":
        key = key_from_keyword(input("Keyword: "))
    else:
        key = random_key()
    if not valid_key(key):
        print("Invalid key: it must use each of the 26 letters exactly once.")
        return None
    print("Key used:", key)
    return key


def main():
    print("=== Monoalphabetic Substitution Cipher ===")
    while True:
        print("\n1. Encrypt\n2. Decrypt\n0. Exit")
        try:
            choice = input("Choice: ").strip()
            if choice in ("1", "2"):
                key = get_key()
                if key is None:
                    continue
                if choice == "1":
                    print("Ciphertext:", encrypt(input("Plaintext : "), key))
                else:
                    print("Plaintext :", decrypt(input("Ciphertext: "), key))
            elif choice == "0":
                break
            else:
                print("Invalid choice.")
        except (EOFError, KeyboardInterrupt):
            print()
            break


if __name__ == "__main__":
    main()
