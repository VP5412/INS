"""
====================================================================
Practical No : 8
Title        : To implement Diffie-Hellman Key Exchange method.
====================================================================
THEORY & LOGIC
 1. Diffie-Hellman (1976) lets two parties, who share no secret, agree
    on a common secret key over an insecure channel; it is the first
    public-key technique and is used only for KEY EXCHANGE.
 2. Public values: a prime p and a generator g (a primitive root of
    p). Everybody, including an attacker, may know p and g.
 3. Alice picks a secret a and sends  A = g^a mod p.
    Bob   picks a secret b and sends  B = g^b mod p.
 4. Alice computes  K = B^a mod p ;  Bob computes  K = A^b mod p.
    Both equal  g^(ab) mod p, which is the shared secret key.
 5. Security rests on the DISCRETE LOGARITHM problem: knowing g, p and
    g^a mod p, finding a is computationally hard for large p.
 6. Fast modular power uses Python's pow(base, exp, mod)
    (square-and-multiply), so even huge numbers are quick.
 7. The program checks that p is prime and that g is a primitive root:
    g^((p-1)/q) mod p must not be 1 for every prime factor q of p-1.
 8. Weakness: the plain protocol is not authenticated, so a
    MAN-IN-THE-MIDDLE (Mallory) can set up one key with Alice and
    another with Bob - option 2 demonstrates this attack.
 9. Example: p=23, g=5, a=6, b=15 -> A=8, B=19, shared key K=2.

Run : python3 p08_diffie_hellman.py
====================================================================
"""
import random


def is_prime(n):
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True


def prime_factors(n):
    factors, i = set(), 2
    while i * i <= n:
        while n % i == 0:
            factors.add(i)
            n //= i
        i += 1
    if n > 1:
        factors.add(n)
    return factors


def is_primitive_root(g, p):
    """g is a primitive root of prime p if its order is p-1."""
    if not 1 < g < p:
        return False
    return all(pow(g, (p - 1) // q, p) != 1 for q in prime_factors(p - 1))


def key_exchange(p, g, a, b, show=True):
    A = pow(g, a, p)                 # Alice's public value
    B = pow(g, b, p)                 # Bob's public value
    key_alice = pow(B, a, p)
    key_bob = pow(A, b, p)
    if show:
        print(f"  Alice: private a = {a}, public A = g^a mod p = {A}")
        print(f"  Bob  : private b = {b}, public B = g^b mod p = {B}")
        print(f"  Alice computes K = B^a mod p = {key_alice}")
        print(f"  Bob   computes K = A^b mod p = {key_bob}")
    return A, B, key_alice, key_bob


def man_in_the_middle(p, g, a, b, m):
    """Mallory (private m) sits between Alice and Bob."""
    A = pow(g, a, p)
    B = pow(g, b, p)
    M = pow(g, m, p)                 # Mallory sends M to both sides
    print(f"  Alice sends A = {A}  -> intercepted by Mallory")
    print(f"  Bob   sends B = {B}  -> intercepted by Mallory")
    print(f"  Mallory sends M = g^m mod p = {M} to BOTH Alice and Bob")
    k_alice = pow(M, a, p)
    k_bob = pow(M, b, p)
    k_m_alice = pow(A, m, p)
    k_m_bob = pow(B, m, p)
    print(f"  Alice's key (with Mallory) = {k_alice}   Mallory has {k_m_alice}")
    print(f"  Bob's   key (with Mallory) = {k_bob}   Mallory has {k_m_bob}")
    print("  Alice and Bob think they share a key, but each shares one with "
          "Mallory,\n  who can decrypt, read and re-encrypt all messages.")
    return k_alice, k_bob, k_m_alice, k_m_bob


def read_int(prompt, low, high):
    while True:
        try:
            value = int(input(prompt))
            if low <= value <= high:
                return value
        except ValueError:
            pass
        print(f"Enter an integer between {low} and {high}.")


def get_public_values():
    p = read_int("Prime number p: ", 3, 10 ** 12)
    if not is_prime(p):
        print(f"{p} is not prime.")
        return None
    g = read_int(f"Generator g (1 < g < {p}): ", 2, p - 1)
    if not is_primitive_root(g, p):
        print(f"{g} is not a primitive root of {p} - the key space would be small.")
        roots = [x for x in range(2, min(p, 50)) if is_primitive_root(x, p)]
        print("Primitive roots (first few):", roots[:8])
        return None
    return p, g


def main():
    print("=== Diffie-Hellman Key Exchange ===")
    while True:
        print("\n1. Key exchange (enter values)\n2. Man-in-the-middle demonstration")
        print("3. Quick example (p=23, g=5, a=6, b=15)\n4. Random example\n0. Exit")
        try:
            choice = input("Choice: ").strip()
            if choice == "0":
                break
            if choice in ("1", "2"):
                values = get_public_values()
                if values is None:
                    continue
                p, g = values
                a = read_int(f"Alice's secret a (1..{p - 2}): ", 1, p - 2)
                b = read_int(f"Bob's secret b (1..{p - 2}): ", 1, p - 2)
                if choice == "1":
                    _, _, ka, kb = key_exchange(p, g, a, b)
                    print("  SUCCESS: both keys are equal." if ka == kb else "  Keys differ!")
                else:
                    m = read_int(f"Mallory's secret m (1..{p - 2}): ", 1, p - 2)
                    man_in_the_middle(p, g, a, b, m)
            elif choice == "3":
                key_exchange(23, 5, 6, 15)
            elif choice == "4":
                p = random.choice([q for q in range(1000, 5000) if is_prime(q)])
                g = random.choice([x for x in range(2, 60) if is_primitive_root(x, p)])
                a, b = random.randint(2, p - 2), random.randint(2, p - 2)
                print(f"  p = {p}, g = {g}")
                key_exchange(p, g, a, b)
            else:
                print("Invalid choice.")
        except (EOFError, KeyboardInterrupt):
            print()
            break


if __name__ == "__main__":
    main()
