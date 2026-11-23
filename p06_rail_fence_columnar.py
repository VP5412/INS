"""
====================================================================
Practical No : 6
Title        : To implement Rail Fence and Columnar transposition
               cipher encryption-decryption.
====================================================================
THEORY & LOGIC
 1. A transposition cipher keeps the plaintext letters unchanged but
    REARRANGES their positions (a permutation); a substitution cipher
    changes the letters but keeps their positions.
 2. RAIL FENCE: the plaintext is written diagonally in a zig-zag over
    'n' rows (rails), going down and then up again:
        W . . . E . . . C . . . R . . . L . . . T . . . E
        . E . R . D . S . O . E . E . F . E . A . O . C .
        . . A . . . I . . . V . . . D . . . E . . . N . .
    The ciphertext is read rail by rail (row by row).
 3. Rail fence decryption: compute the zig-zag positions again, count
    how many letters each rail holds, cut the ciphertext into these
    rails and read the zig-zag order to get the plaintext.
 4. COLUMNAR: the plaintext is written in rows under a keyword; the
    columns are read out in the ALPHABETICAL order of the key letters
    (equal letters are ordered left to right).
 5. If the last row is incomplete it is padded with 'X' so every
    column has the same length (this makes decryption simple).
 6. Columnar decryption: the ciphertext is cut into equal columns,
    the columns are put back under their key positions, and the text
    is read row by row.
 7. Example: rail fence, 3 rails, WEAREDISCOVEREDFLEEATONCE ->
    WECRLTEERDSOEEFEAOCAIVDEN.
 8. Example: columnar, key ZEBRAS, the same text -> starts with
    EVLN (first column read is the letter A of the key).
 9. Security: both keep the letter frequencies, so they are weak alone;
    they are combined with substitution in modern block ciphers.

Run : python3 p06_rail_fence_columnar.py
====================================================================
"""
import math


# ---------------------------- RAIL FENCE ----------------------------
def rail_pattern(length, rails):
    """Rail number of every position of the zig-zag."""
    if rails == 1:
        return [0] * length
    pattern, rail, step = [], 0, 1
    for _ in range(length):
        pattern.append(rail)
        if rail == 0:
            step = 1
        elif rail == rails - 1:
            step = -1
        rail += step
    return pattern


def rail_encrypt(text, rails):
    pattern = rail_pattern(len(text), rails)
    return "".join(text[i] for r in range(rails)
                   for i in range(len(text)) if pattern[i] == r)


def rail_decrypt(cipher, rails):
    pattern = rail_pattern(len(cipher), rails)
    # positions in the order in which they were written to the cipher text
    order = sorted(range(len(cipher)), key=lambda i: (pattern[i], i))
    plain = [""] * len(cipher)
    for k, pos in enumerate(order):
        plain[pos] = cipher[k]
    return "".join(plain)


# --------------------------- COLUMNAR -------------------------------
def column_order(key):
    """Column numbers sorted by key letter (ties: left to right)."""
    return sorted(range(len(key)), key=lambda i: (key[i], i))


def clean(text):
    return "".join(c for c in text.upper() if c.isalnum() and c.isascii())


def columnar_encrypt(text, key, pad="X"):
    key, text = key.upper(), clean(text)
    cols = len(key)
    rows = math.ceil(len(text) / cols)
    text += pad * (rows * cols - len(text))
    return "".join(text[c::cols] for c in column_order(key))


def columnar_decrypt(cipher, key):
    key, cipher = key.upper(), clean(cipher)
    cols = len(key)
    if len(cipher) % cols:
        raise ValueError("ciphertext length must be a multiple of the key length")
    rows = len(cipher) // cols
    columns = {}
    for k, c in enumerate(column_order(key)):
        columns[c] = cipher[k * rows:(k + 1) * rows]
    return "".join(columns[c][r] for r in range(rows) for c in range(cols))


def read_int(prompt, minimum):
    while True:
        try:
            value = int(input(prompt))
            if value >= minimum:
                return value
        except ValueError:
            pass
        print(f"Enter an integer >= {minimum}.")


def main():
    print("=== Rail Fence and Columnar Transposition ===")
    while True:
        print("\n1. Rail fence encrypt\n2. Rail fence decrypt")
        print("3. Columnar encrypt\n4. Columnar decrypt\n0. Exit")
        try:
            choice = input("Choice: ").strip()
            if choice == "0":
                break
            if choice in ("1", "2"):
                text = input("Text (spaces are removed): ").replace(" ", "")
                rails = read_int("Number of rails: ", 2)
                func = rail_encrypt if choice == "1" else rail_decrypt
                print("Result:", func(text, rails))
            elif choice in ("3", "4"):
                key = input("Keyword: ").strip()
                if not key:
                    print("Keyword required.")
                    continue
                text = input("Text: ")
                if choice == "3":
                    print("Result:", columnar_encrypt(text, key))
                else:
                    print("Result:", columnar_decrypt(text, key))
            else:
                print("Invalid choice.")
        except ValueError as err:
            print("Error:", err)
        except (EOFError, KeyboardInterrupt):
            print()
            break


if __name__ == "__main__":
    main()
