"""
====================================================================
Practical No : 9
Title        : To implement RSA encryption-decryption algorithm.
====================================================================
THEORY & LOGIC
 1. RSA (Rivest, Shamir, Adleman, 1977) is a public-key (asymmetric)
    cipher: a PUBLIC key (e, n) encrypts and a PRIVATE key (d, n)
    decrypts, so no secret has to be shared beforehand.
 2. KEY GENERATION
      a) choose two distinct primes p and q
      b) n = p * q               (the modulus)
      c) phi(n) = (p-1)(q-1)     (Euler's totient)
      d) choose e with 1 < e < phi and gcd(e, phi) = 1   (public)
      e) d = e^-1 mod phi        (private) via extended Euclid
 3. ENCRYPTION :  C = M^e mod n        (message number M < n)
    DECRYPTION :  M = C^d mod n
 4. It works because e*d = 1 + k*phi(n) and Euler's theorem gives
    M^(e*d) = M (mod n).
 5. Modular exponentiation uses the fast square-and-multiply method,
    and the inverse d is found with the extended Euclidean algorithm
    (both are written out in the program).
 6. Security rests on the difficulty of FACTORING n into p and q; real
    keys use primes of 1024+ bits (the demo uses small primes).
 7. Text is encrypted character by character: each ASCII code is one
    block, so n must be greater than 255.
 8. Plain 'textbook' RSA is deterministic; real systems add padding
    (OAEP) and encrypt only a session key.
 9. Example: p=61, q=53 -> n=3233, phi=3120, e=17, d=2753;
    message 65 -> ciphertext 2790 -> back to 65.

Run : python3 p09_rsa.py
====================================================================
"""
import random


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """Return (g, x, y) with a*x + b*y = g = gcd(a, b)."""
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def mod_inverse(e, phi):
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("e and phi(n) are not coprime")
    return x % phi


def mod_exp(base, exp, mod):
    """Square-and-multiply: base^exp mod mod."""
    result, base = 1, base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def is_prime(n):
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True


def random_prime(low=100, high=1000):
    while True:
        n = random.randint(low, high)
        if is_prime(n):
            return n


def generate_keys(p, q, e=None):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("p and q must both be prime")
    if p == q:
        raise ValueError("p and q must be different")
    n, phi = p * q, (p - 1) * (q - 1)
    if e is None:                                  # pick the smallest good e
        e = next(x for x in range(3, phi, 2) if gcd(x, phi) == 1)
    if not (1 < e < phi and gcd(e, phi) == 1):
        raise ValueError(f"e must satisfy 1 < e < {phi} and gcd(e, {phi}) = 1")
    d = mod_inverse(e, phi)
    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}


def encrypt_number(m, e, n):
    if not 0 <= m < n:
        raise ValueError("message number must be smaller than n")
    return mod_exp(m, e, n)


def decrypt_number(c, d, n):
    return mod_exp(c, d, n)


def encrypt_text(text, e, n):
    if n <= 255:
        raise ValueError("n must be larger than 255 to encrypt characters")
    return [encrypt_number(ord(ch), e, n) for ch in text]


def decrypt_text(numbers, d, n):
    return "".join(chr(decrypt_number(c, d, n)) for c in numbers)


def read_int(prompt, default=None):
    while True:
        raw = input(prompt).strip()
        if raw == "" and default is not None:
            return default
        try:
            return int(raw)
        except ValueError:
            print("Enter an integer.")


def main():
    print("=== RSA Algorithm ===")
    try:
        print("Enter two primes (use at least 17 and 19 so that n > 255), "
              "or press Enter for random primes.")
        raw = input("p: ").strip()
        if raw:
            p, q = int(raw), read_int("q: ")
        else:
            p = random_prime()
            q = random_prime()
            while q == p:
                q = random_prime()
        e_in = input("e (press Enter to choose automatically): ").strip()
        keys = generate_keys(p, q, int(e_in) if e_in else None)
    except ValueError as err:
        print("Error:", err)
        return
    except (EOFError, KeyboardInterrupt):
        print()
        return

    print(f"\n p = {keys['p']}, q = {keys['q']}")
    print(f" n = p*q = {keys['n']},  phi(n) = {keys['phi']}")
    print(f" Public key  (e, n) = ({keys['e']}, {keys['n']})")
    print(f" Private key (d, n) = ({keys['d']}, {keys['n']})")

    while True:
        print("\n1. Encrypt text\n2. Decrypt numbers\n"
              "3. Encrypt a number\n4. Decrypt a number\n0. Exit")
        try:
            choice = input("Choice: ").strip()
            if choice == "0":
                break
            if choice == "1":
                cipher = encrypt_text(input("Plaintext: "), keys["e"], keys["n"])
                print("Ciphertext:", " ".join(map(str, cipher)))
            elif choice == "2":
                nums = [int(x) for x in input("Ciphertext numbers: ").split()]
                print("Plaintext:", decrypt_text(nums, keys["d"], keys["n"]))
            elif choice == "3":
                print("Ciphertext:", encrypt_number(read_int("Message number: "),
                                                    keys["e"], keys["n"]))
            elif choice == "4":
                print("Message   :", decrypt_number(read_int("Ciphertext number: "),
                                                    keys["d"], keys["n"]))
            else:
                print("Invalid choice.")
        except (ValueError, OverflowError) as err:
            print("Error:", err)
        except (EOFError, KeyboardInterrupt):
            print()
            break


if __name__ == "__main__":
    main()
