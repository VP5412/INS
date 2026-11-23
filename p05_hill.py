"""
====================================================================
Practical No : 5
Title        : To implement Hill cipher encryption-decryption.
====================================================================
THEORY & LOGIC
 1. The Hill cipher (Lester Hill, 1929) is a polygraphic substitution
    cipher based on linear algebra: it encrypts a block of n letters
    at once using an n x n key matrix K.
 2. Letters are numbered A=0 ... Z=25 and all arithmetic is mod 26.
 3. Plaintext is cut into blocks of n letters, each block is a column
    vector P.  Encryption :  C = K . P  (mod 26)
 4. Decryption needs the INVERSE matrix:  P = K^-1 . C  (mod 26)
    where  K^-1 = det(K)^-1 . adj(K)  (mod 26).
 5. K is usable only if gcd(det(K), 26) = 1; otherwise det(K) has no
    inverse mod 26 and decryption is impossible (the program checks).
 6. The modular inverse of the determinant is found with Python's
    pow(d, -1, 26); the adjugate is built from cofactors (minors with
    alternating signs, transposed).
 7. If the last block is short it is padded with the letter X.
 8. Example (n = 3): key GYBNQKURP, plaintext ACT -> ciphertext POH.
    Example (n = 2): key [[3,3],[2,5]] (letters DDCF), HELP -> HIAT.
 9. Strength: it hides single-letter and (for n=2) digraph statistics;
    weakness: it is linear, so a known-plaintext attack with n
    independent blocks recovers the key.

Run : python3 p05_hill.py
====================================================================
"""
import math


def to_nums(text):
    return [ord(c) - ord("A") for c in text.upper() if c.isalpha() and c.isascii()]


def to_text(nums):
    return "".join(chr(n % 26 + ord("A")) for n in nums)


def key_matrix(key_text):
    """Turn a key word of n*n letters into an n x n matrix."""
    nums = to_nums(key_text)
    n = int(math.isqrt(len(nums)))
    if n < 2 or n * n != len(nums):
        raise ValueError("key length must be a perfect square (4, 9 or 16 letters)")
    return [nums[i * n:(i + 1) * n] for i in range(n)]


def minor(m, i, j):
    """Matrix m without row i and column j."""
    return [row[:j] + row[j + 1:] for k, row in enumerate(m) if k != i]


def det(m):
    """Determinant by cofactor expansion along the first row."""
    if len(m) == 1:
        return m[0][0]
    return sum(((-1) ** j) * m[0][j] * det(minor(m, 0, j)) for j in range(len(m)))


def inverse_matrix(m):
    """Inverse of m modulo 26 (raises ValueError if it does not exist)."""
    d = det(m) % 26
    if math.gcd(d, 26) != 1:
        raise ValueError(f"determinant {d} has no inverse mod 26 - choose another key")
    inv_d = pow(d, -1, 26)
    n = len(m)
    if n == 1:
        return [[inv_d]]
    # adjugate = transpose of the cofactor matrix
    return [[(inv_d * ((-1) ** (i + j)) * det(minor(m, j, i))) % 26
             for j in range(n)] for i in range(n)]


def multiply_blocks(nums, m):
    n = len(m)
    out = []
    for s in range(0, len(nums), n):
        block = nums[s:s + n]
        for row in m:
            out.append(sum(a * b for a, b in zip(row, block)) % 26)
    return out


def encrypt(plain, m):
    nums = to_nums(plain)
    while len(nums) % len(m):
        nums.append(ord("X") - ord("A"))               # pad with X
    return to_text(multiply_blocks(nums, m))


def decrypt(cipher, m):
    nums = to_nums(cipher)
    if len(nums) % len(m):
        raise ValueError("ciphertext length must be a multiple of the key size")
    return to_text(multiply_blocks(nums, inverse_matrix(m)))


def show(m, title):
    print(title)
    for row in m:
        print("  " + " ".join(f"{v:2d}" for v in row))


def main():
    print("=== Hill Cipher ===")
    while True:
        print("\n1. Encrypt\n2. Decrypt\n0. Exit")
        try:
            choice = input("Choice: ").strip()
            if choice == "0":
                break
            if choice not in ("1", "2"):
                print("Invalid choice.")
                continue
            m = key_matrix(input("Key (4 letters for 2x2, 9 for 3x3): "))
            show(m, "Key matrix:")
            if choice == "1":
                inverse_matrix(m)                      # make sure key is valid
                print("Ciphertext:", encrypt(input("Plaintext : "), m))
            else:
                show(inverse_matrix(m), "Inverse key matrix (mod 26):")
                print("Plaintext :", decrypt(input("Ciphertext: "), m))
        except ValueError as err:
            print("Error:", err)
        except (EOFError, KeyboardInterrupt):
            print()
            break


if __name__ == "__main__":
    main()
