"""
====================================================================
Practical No : 1
Title        : To implement Caesar cipher encryption-decryption.
====================================================================
THEORY & LOGIC
 1. The Caesar cipher is the oldest and simplest substitution cipher,
    said to be used by Julius Caesar (with a shift of 3).
 2. Every letter of the plaintext is replaced by the letter that is
    'key' positions further along in the alphabet (a shift cipher).
 3. Letters are numbered A=0, B=1 ... Z=25 and the arithmetic is done
    modulo 26, so the alphabet wraps around (Z + 1 -> A).
 4. Encryption :  C = (P + k) mod 26
    Decryption :  P = (C - k) mod 26        (k = secret key, 0..25)
 5. Python's % operator always returns a non-negative result, so the
    decryption formula needs no special handling of negative values.
 6. Upper-case and lower-case letters are shifted separately so the
    case of the text is kept; digits, spaces and symbols are copied
    without change.
 7. Security: there are only 25 useful keys, so the cipher is broken
    by BRUTE FORCE (try all shifts) in seconds - option 3 shows this.
 8. It is also weak against frequency analysis because the letter
    frequencies of the plaintext are only shifted, not hidden.
 9. Example: plaintext HELLO, key 3  ->  ciphertext KHOOR.

Run : python3 p01_caesar.py
====================================================================
"""


def caesar(text, key, decrypt=False):
    """Shift every letter of text by key (backwards when decrypt=True)."""
    shift = -key if decrypt else key
    result = []
    for ch in text:
        if ch.isupper() and ch.isascii():
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        elif ch.islower() and ch.isascii():
            result.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        else:
            result.append(ch)              # digits, spaces, symbols
    return "".join(result)


def brute_force(cipher_text):
    """Return all 26 possible decryptions (cryptanalysis)."""
    return [(k, caesar(cipher_text, k, decrypt=True)) for k in range(26)]


def read_key():
    while True:
        try:
            return int(input("Enter key (integer): ")) % 26
        except ValueError:
            print("Key must be an integer.")


def main():
    print("=== Caesar Cipher ===")
    while True:
        print("\n1. Encrypt\n2. Decrypt\n3. Brute-force attack\n0. Exit")
        try:
            choice = input("Choice: ").strip()
            if choice == "1":
                text = input("Plaintext : ")
                print("Ciphertext:", caesar(text, read_key()))
            elif choice == "2":
                text = input("Ciphertext: ")
                print("Plaintext :", caesar(text, read_key(), decrypt=True))
            elif choice == "3":
                text = input("Ciphertext: ")
                for k, plain in brute_force(text):
                    print(f"  key {k:2d} -> {plain}")
            elif choice == "0":
                break
            else:
                print("Invalid choice.")
        except (EOFError, KeyboardInterrupt):
            print()
            break


if __name__ == "__main__":
    main()
