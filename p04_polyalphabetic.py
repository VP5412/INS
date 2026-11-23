"""
====================================================================
Practical No : 4
Title        : To implement Polyalphabetic cipher encryption-decryption
               (Vigenere cipher and Autokey cipher).
====================================================================
THEORY & LOGIC
 1. A polyalphabetic cipher uses SEVERAL substitution alphabets, so
    the same plaintext letter can give different ciphertext letters.
    This hides the letter-frequency pattern of the language.
 2. Vigenere cipher: the key is a word that is repeated under the
    plaintext; each key letter (A=0 ... Z=25) is a Caesar shift for
    the plaintext letter above it.
 3. Encryption :  C(i) = (P(i) + K(i mod m)) mod 26      (m = key length)
    Decryption :  P(i) = (C(i) - K(i mod m)) mod 26
 4. Example: ATTACKATDAWN with key LEMON -> LXFOPVEFRNHR
        plaintext : A T T A C K A T D A W N
        key       : L E M O N L E M O N L E
 5. Autokey cipher: the key is the secret word followed by the
    PLAINTEXT itself, so the key never repeats:
        stream = KEY + P(0) P(1) P(2) ...
 6. For autokey decryption the key stream is rebuilt with every
    plaintext letter that has just been recovered.
 7. The key letter index advances only on letters; spaces, digits and
    punctuation are copied unchanged and the case is preserved.
 8. Security: Vigenere is broken by the Kasiski test / index of
    coincidence once the key length is found (see Practical 10 demo);
    autokey removes the repeating key, but is still breakable.
 9. A key as long as the message used only once is the one-time pad.

Run : python3 p04_polyalphabetic.py
====================================================================
"""


def letters_only(text):
    return "".join(c for c in text.upper() if c.isalpha() and c.isascii())


def vigenere(text, key, decrypt=False):
    key = letters_only(key)
    if not key:
        raise ValueError("key must contain letters")
    out, j = [], 0
    for ch in text:
        if ch.isalpha() and ch.isascii():
            shift = ord(key[j % len(key)]) - ord("A")
            if decrypt:
                shift = -shift
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def autokey(text, key, decrypt=False):
    stream = [ord(c) - ord("A") for c in letters_only(key)]
    if not stream:
        raise ValueError("key must contain letters")
    out, j = [], 0
    for ch in text:
        if ch.isalpha() and ch.isascii():
            base = ord("A") if ch.isupper() else ord("a")
            x = ord(ch) - base
            k = stream[j]
            if decrypt:
                y = (x - k) % 26
                stream.append(y)            # recovered plaintext extends key
            else:
                y = (x + k) % 26
                stream.append(x)            # plaintext extends key
            out.append(chr(y + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def main():
    print("=== Polyalphabetic Cipher ===")
    while True:
        print("\n1. Vigenere encrypt\n2. Vigenere decrypt")
        print("3. Autokey encrypt\n4. Autokey decrypt\n0. Exit")
        try:
            choice = input("Choice: ").strip()
            if choice == "0":
                break
            if choice not in ("1", "2", "3", "4"):
                print("Invalid choice.")
                continue
            key = input("Key (word): ")
            text = input("Text: ")
            func = vigenere if choice in ("1", "2") else autokey
            print("Result:", func(text, key, decrypt=choice in ("2", "4")))
        except ValueError as err:
            print("Error:", err)
        except (EOFError, KeyboardInterrupt):
            print()
            break


if __name__ == "__main__":
    main()
