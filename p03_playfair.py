"""
====================================================================
Practical No : 3
Title        : To implement Playfair cipher encryption-decryption.
====================================================================
THEORY & LOGIC
 1. Playfair (Charles Wheatstone, 1854) is a DIGRAPH substitution
    cipher: it encrypts pairs of letters, not single letters, so the
    letter frequencies are flattened.
 2. A 5x5 key matrix is built: write the keyword (no repeats) and then
    the rest of the alphabet; I and J share one cell (J -> I).
 3. The plaintext is split into pairs. If both letters of a pair are
    equal, an 'X' is inserted between them; if one letter is left at
    the end, an 'X' is added as padding.
 4. Rule 1 (same ROW)    : replace each letter by the one on its RIGHT
                           (wrap from the last column to the first).
 5. Rule 2 (same COLUMN) : replace each letter by the one BELOW it
                           (wrap from the last row to the first).
 6. Rule 3 (rectangle)   : replace each letter by the letter in its own
                           row but in the column of the other letter.
 7. Decryption uses the same rules in the opposite direction (LEFT for
    rows, UP for columns, rectangle rule unchanged).
 8. The inserted X letters stay in the decrypted text; the program also
    prints a cleaned guess with the filler X removed.
 9. Example: key PLAYFAIR EXAMPLE, "Hide the gold in the tree stump"
    -> BMODZBXDNABEKUDMUIXMMOUVIF.

Run : python3 p03_playfair.py
====================================================================
"""
import string

ALPHABET = string.ascii_uppercase.replace("J", "")      # 25 letters


def clean(text):
    """Keep letters only, upper case, J -> I."""
    return "".join(c for c in text.upper() if c.isalpha() and c.isascii()).replace("J", "I")


def build_matrix(key):
    seen = []
    for ch in clean(key) + ALPHABET:
        if ch not in seen:
            seen.append(ch)
    return [seen[i * 5:(i + 1) * 5] for i in range(5)]


def make_pairs(text):
    """Split into digraphs; insert X between equal letters, pad with X."""
    text = clean(text)
    pairs, i = [], 0
    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else None
        if b is None or a == b:
            pairs.append(a + "X")          # filler X, move on by ONE letter
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def process_pair(pair, matrix, direction):
    """direction = +1 for encryption, -1 for decryption."""
    pos = {matrix[r][c]: (r, c) for r in range(5) for c in range(5)}
    (r1, c1), (r2, c2) = pos[pair[0]], pos[pair[1]]
    if r1 == r2:                                         # same row
        return matrix[r1][(c1 + direction) % 5] + matrix[r2][(c2 + direction) % 5]
    if c1 == c2:                                         # same column
        return matrix[(r1 + direction) % 5][c1] + matrix[(r2 + direction) % 5][c2]
    return matrix[r1][c2] + matrix[r2][c1]               # rectangle


def encrypt(plain, key):
    matrix = build_matrix(key)
    return "".join(process_pair(p, matrix, +1) for p in make_pairs(plain))


def decrypt(cipher, key):
    matrix = build_matrix(key)
    cipher = clean(cipher)
    if len(cipher) % 2:
        raise ValueError("ciphertext length must be even")
    pairs = [cipher[i:i + 2] for i in range(0, len(cipher), 2)]
    return "".join(process_pair(p, matrix, -1) for p in pairs)


def remove_fillers(text):
    """Guess: drop X between two equal letters and a trailing X."""
    out = []
    for i, ch in enumerate(text):
        if ch == "X" and 0 < i < len(text) - 1 and text[i - 1] == text[i + 1]:
            continue
        out.append(ch)
    if out and out[-1] == "X":
        out.pop()
    return "".join(out)


def show_matrix(matrix):
    print("Key matrix:")
    for row in matrix:
        print("  " + " ".join(row))


def main():
    print("=== Playfair Cipher ===")
    while True:
        print("\n1. Encrypt\n2. Decrypt\n0. Exit")
        try:
            choice = input("Choice: ").strip()
            if choice in ("1", "2"):
                key = input("Keyword: ")
                if not clean(key):
                    print("Keyword must contain letters.")
                    continue
                show_matrix(build_matrix(key))
                if choice == "1":
                    text = input("Plaintext : ")
                    print("Digraphs  :", " ".join(make_pairs(text)))
                    print("Ciphertext:", encrypt(text, key))
                else:
                    raw = decrypt(input("Ciphertext: "), key)
                    print("Plaintext (raw)    :", raw)
                    print("Plaintext (cleaned):", remove_fillers(raw))
            elif choice == "0":
                break
            else:
                print("Invalid choice.")
        except ValueError as err:
            print("Error:", err)
        except (EOFError, KeyboardInterrupt):
            print()
            break


if __name__ == "__main__":
    main()
