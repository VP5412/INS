"""
====================================================================
Practical No : 7
Title        : To implement Simplified Data Encryption Standard (S-DES).
====================================================================
THEORY & LOGIC
 1. S-DES (Edward Schaefer) is a small teaching version of DES. It
    encrypts an 8-bit block with a 10-bit key and has the same
    structure: permutations, a Feistel network and S-boxes.
 2. KEY GENERATION: key -> P10 -> split into two 5-bit halves ->
    circular left shift 1 -> P8 gives K1; shift both halves 2 more
    positions -> P8 gives K2.
 3. ENCRYPTION:  IP -> f_K(K1) -> SW (swap halves) -> f_K(K2) -> IP^-1
 4. The function f_K works on a left half L and right half R:
        f_K(L, R) = ( L XOR F(R, K) , R )
 5. F(R, K): expand R from 4 to 8 bits with E/P, XOR with the subkey,
    send the left 4 bits through S-box S0 and the right 4 bits
    through S1 (each gives 2 bits), then apply the permutation P4.
 6. S-box lookup: the outer bits (1st and 4th) select the ROW and the
    middle two bits select the COLUMN of the 4x4 table.
 7. DECRYPTION is the same algorithm with the subkeys used in reverse
    order (K2 first, then K1) - a property of Feistel networks.
 8. Text mode: every character (8 bits) is encrypted separately
    (ECB mode); the ciphertext is shown in hexadecimal.
 9. Test: key 1010000010 gives K1 = 10100100, K2 = 01000011;
    plaintext 01110010 -> ciphertext 01110111.
    S-DES is NOT secure (only 1024 keys); it is only for learning.

Run : python3 p07_simplified_des.py
====================================================================
"""

P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)
P4 = (2, 4, 3, 1)

S0 = ((1, 0, 3, 2),
      (3, 2, 1, 0),
      (0, 2, 1, 3),
      (3, 1, 3, 2))
S1 = ((0, 1, 2, 3),
      (2, 0, 1, 3),
      (3, 0, 1, 0),
      (2, 1, 0, 3))


def permute(bits, table):
    return "".join(bits[i - 1] for i in table)


def left_shift(bits, n):
    return bits[n:] + bits[:n]


def xor(a, b):
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def generate_keys(key10):
    p = permute(key10, P10)
    left, right = p[:5], p[5:]
    left, right = left_shift(left, 1), left_shift(right, 1)
    k1 = permute(left + right, P8)
    left, right = left_shift(left, 2), left_shift(right, 2)
    k2 = permute(left + right, P8)
    return k1, k2


def sbox(bits4, box):
    row = int(bits4[0] + bits4[3], 2)           # outer bits
    col = int(bits4[1:3], 2)                    # middle bits
    return format(box[row][col], "02b")


def f_k(bits8, subkey, verbose=False):
    left, right = bits8[:4], bits8[4:]
    expanded = permute(right, EP)
    mixed = xor(expanded, subkey)
    s_out = sbox(mixed[:4], S0) + sbox(mixed[4:], S1)
    p4 = permute(s_out, P4)
    if verbose:
        print(f"    E/P={expanded}  XOR key={mixed}  S-boxes={s_out}  P4={p4}")
    return xor(left, p4) + right


def process_block(block8, key10, decrypt=False, verbose=False):
    k1, k2 = generate_keys(key10)
    if decrypt:
        k1, k2 = k2, k1
    if verbose:
        print(f"  K1 = {k1}   K2 = {k2}")
    bits = permute(block8, IP)
    if verbose:
        print(f"  after IP        : {bits}")
    bits = f_k(bits, k1, verbose)
    if verbose:
        print(f"  after f_K(K1)   : {bits}")
    bits = bits[4:] + bits[:4]                  # SW
    if verbose:
        print(f"  after swap      : {bits}")
    bits = f_k(bits, k2, verbose)
    if verbose:
        print(f"  after f_K(K2)   : {bits}")
    return permute(bits, IP_INV)


def encrypt_text(text, key10):
    return "".join(format(int(process_block(format(ord(ch), "08b"), key10), 2), "02X")
                   for ch in text)


def decrypt_text(hex_text, key10):
    hex_text = hex_text.replace(" ", "")
    if len(hex_text) % 2:
        raise ValueError("hex ciphertext must have an even number of digits")
    chars = []
    for i in range(0, len(hex_text), 2):
        block = format(int(hex_text[i:i + 2], 16), "08b")
        chars.append(chr(int(process_block(block, key10, decrypt=True), 2)))
    return "".join(chars)


def is_bits(s, n):
    return len(s) == n and set(s) <= {"0", "1"}


def main():
    print("=== Simplified DES (S-DES) ===")
    while True:
        print("\n1. Encrypt 8-bit block\n2. Decrypt 8-bit block")
        print("3. Encrypt text\n4. Decrypt text (hex)\n0. Exit")
        try:
            choice = input("Choice: ").strip()
            if choice == "0":
                break
            if choice not in ("1", "2", "3", "4"):
                print("Invalid choice.")
                continue
            key = input("10-bit key: ").strip()
            if not is_bits(key, 10):
                print("Key must be exactly 10 bits (0/1).")
                continue
            if choice in ("1", "2"):
                block = input("8-bit block: ").strip()
                if not is_bits(block, 8):
                    print("Block must be exactly 8 bits (0/1).")
                    continue
                print("Result:", process_block(block, key, decrypt=(choice == "2"),
                                               verbose=True))
            elif choice == "3":
                text = input("Plaintext: ")
                if any(ord(c) > 255 for c in text):
                    print("Only characters with code below 256 are supported.")
                    continue
                print("Ciphertext (hex):", encrypt_text(text, key))
            else:
                print("Plaintext:", decrypt_text(input("Ciphertext (hex): "), key))
        except ValueError as err:
            print("Error:", err)
        except (EOFError, KeyboardInterrupt):
            print()
            break


if __name__ == "__main__":
    main()
