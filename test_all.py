"""
Self-test: checks every program against known textbook / reference values.
Run : python3 test_all.py
"""
import p01_caesar as p1
import p02_monoalphabetic as p2
import p03_playfair as p3
import p04_polyalphabetic as p4
import p05_hill as p5
import p06_rail_fence_columnar as p6
import p07_simplified_des as p7
import p08_diffie_hellman as p8
import p09_rsa as p9

passed = failed = 0


def check(name, got, expected):
    global passed, failed
    if got == expected:
        passed += 1
        print(f"PASS  {name}")
    else:
        failed += 1
        print(f"FAIL  {name}\n      got      : {got!r}\n      expected : {expected!r}")


# 1 Caesar
check("Caesar encrypt", p1.caesar("HELLO, World!", 3), "KHOOR, Zruog!")
check("Caesar decrypt", p1.caesar("KHOOR, Zruog!", 3, decrypt=True), "HELLO, World!")
check("Caesar key 29 = 3", p1.caesar("abc", 29), "def")
check("Caesar brute force contains plaintext",
      ("ATTACK AT DAWN" in [t for _, t in p1.brute_force(p1.caesar("ATTACK AT DAWN", 11))]), True)

# 2 Monoalphabetic
KEY = "QWERTYUIOPASDFGHJKLZXCVBNM"
check("Mono encrypt", p2.encrypt("Hello", KEY), "Itssg")
check("Mono decrypt", p2.decrypt("Itssg", KEY), "Hello")
check("Mono keyword key", p2.key_from_keyword("zebras"), "ZEBRASCDFGHIJKLMNOPQTUVWXY")
check("Mono key validation", (p2.valid_key(KEY), p2.valid_key("ABC")), (True, False))
rk = p2.random_key()
check("Mono random key round trip", p2.decrypt(p2.encrypt("Test 123", rk), rk), "Test 123")

# 3 Playfair
check("Playfair encrypt", p3.encrypt("Hide the gold in the tree stump", "playfair example"),
      "BMODZBXDNABEKUDMUIXMMOUVIF")
check("Playfair decrypt", p3.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF", "playfair example"),
      "HIDETHEGOLDINTHETREXESTUMP")
check("Playfair double letters", p3.make_pairs("balloon"), ["BA", "LX", "LO", "ON"])
check("Playfair round trip odd length", p3.decrypt(p3.encrypt("abc", "key"), "key"), "ABCX")

# 4 Polyalphabetic
check("Vigenere encrypt", p4.vigenere("ATTACKATDAWN", "LEMON"), "LXFOPVEFRNHR")
check("Vigenere decrypt", p4.vigenere("LXFOPVEFRNHR", "LEMON", decrypt=True), "ATTACKATDAWN")
check("Vigenere keeps case/symbols", p4.vigenere("Hi, You!", "key"), "Rm, Wyy!")
check("Vigenere round trip", p4.vigenere(p4.vigenere("Hi, You!", "key"), "key", True), "Hi, You!")
check("Autokey encrypt", p4.autokey("ATTACKATDAWN", "QUEENLY"), "QNXEPVYTWTWP")
check("Autokey decrypt", p4.autokey("QNXEPVYTWTWP", "QUEENLY", decrypt=True), "ATTACKATDAWN")

# 5 Hill
m3 = p5.key_matrix("GYBNQKURP")
check("Hill 3x3 encrypt", p5.encrypt("ACT", m3), "POH")
check("Hill 3x3 decrypt", p5.decrypt("POH", m3), "ACT")
m2 = [[3, 3], [2, 5]]
check("Hill 2x2 encrypt", p5.encrypt("HELP", m2), "HIAT")
check("Hill 2x2 decrypt", p5.decrypt("HIAT", m2), "HELP")
check("Hill inverse 2x2", p5.inverse_matrix(m2), [[15, 17], [20, 9]])
check("Hill padding", p5.encrypt("HEL", m2), p5.encrypt("HELX", m2))
try:
    p5.inverse_matrix([[2, 4], [1, 2]])
    check("Hill singular key rejected", "accepted", "rejected")
except ValueError:
    check("Hill singular key rejected", "rejected", "rejected")

# 6 Rail fence / columnar
check("Rail fence encrypt", p6.rail_encrypt("WEAREDISCOVEREDFLEEATONCE", 3),
      "WECRLTEERDSOEEFEAOCAIVDEN")
check("Rail fence decrypt", p6.rail_decrypt("WECRLTEERDSOEEFEAOCAIVDEN", 3),
      "WEAREDISCOVEREDFLEEATONCE")
check("Rail fence 1 rail", p6.rail_encrypt("HELLO", 1), "HELLO")
check("Rail fence round trip 4 rails", p6.rail_decrypt(p6.rail_encrypt("ABCDEFGHIJK", 4), 4),
      "ABCDEFGHIJK")
ct = p6.columnar_encrypt("WEAREDISCOVEREDFLEEATONCE", "ZEBRAS")
check("Columnar full ciphertext (hand-worked)", ct, "EVLNXACDTXESEAXROFOXDEECXWIREE")
check("Columnar starts EVLN", ct[:4], "EVLN")
check("Columnar length padded", len(ct), 30)
check("Columnar round trip", p6.columnar_decrypt(ct, "ZEBRAS").rstrip("X"),
      "WEAREDISCOVEREDFLEEATONCE")
check("Columnar sort order ZEBRAS", p6.column_order("ZEBRAS"), [4, 2, 1, 3, 5, 0])

# 7 S-DES
check("S-DES keys", p7.generate_keys("1010000010"), ("10100100", "01000011"))
check("S-DES encrypt", p7.process_block("01110010", "1010000010"), "01110111")
check("S-DES decrypt", p7.process_block("01110111", "1010000010", decrypt=True), "01110010")
allok = all(p7.process_block(p7.process_block(format(b, "08b"), "0110101101"),
                             "0110101101", decrypt=True) == format(b, "08b")
            for b in range(256))
check("S-DES round trip all 256 blocks", allok, True)
check("S-DES text round trip", p7.decrypt_text(p7.encrypt_text("Hello INS!", "1100011110"),
                                               "1100011110"), "Hello INS!")

# 8 Diffie-Hellman
A, B, ka, kb = p8.key_exchange(23, 5, 6, 15, show=False)
check("DH values", (A, B, ka, kb), (8, 19, 2, 2))
check("DH primitive root of 23", [g for g in range(2, 23) if p8.is_primitive_root(g, 23)],
      [5, 7, 10, 11, 14, 15, 17, 19, 20, 21])
check("DH not prime", (p8.is_prime(21), p8.is_prime(23)), (False, True))
import io, contextlib
with contextlib.redirect_stdout(io.StringIO()):
    k_a, k_b, k_ma, k_mb = p8.man_in_the_middle(23, 5, 6, 15, 9)
check("MITM Mallory knows both keys", (k_a == k_ma, k_b == k_mb), (True, True))
check("MITM Alice and Bob differ", k_a != k_b, True)

# 9 RSA
k = p9.generate_keys(61, 53, 17)
check("RSA keys", (k["n"], k["phi"], k["e"], k["d"]), (3233, 3120, 17, 2753))
check("RSA encrypt 65", p9.encrypt_number(65, 17, 3233), 2790)
check("RSA decrypt 2790", p9.decrypt_number(2790, 2753, 3233), 65)
check("RSA text round trip", p9.decrypt_text(p9.encrypt_text("Secure Message 123!", k["e"], k["n"]),
                                              k["d"], k["n"]), "Secure Message 123!")
check("RSA mod_exp = pow", p9.mod_exp(7, 560, 561), pow(7, 560, 561))
check("RSA mod_inverse", p9.mod_inverse(3, 11), 4)
check("RSA auto e", p9.generate_keys(17, 19)["e"], 5)
try:
    p9.generate_keys(15, 19)
    check("RSA rejects composite", "accepted", "rejected")
except ValueError:
    check("RSA rejects composite", "rejected", "rejected")

print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
