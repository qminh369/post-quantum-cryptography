"""Kiểm thử HQC. Chạy từ thư mục Implementation:  python -m unittest -v"""

import random
import secrets
import unittest

from hqc import ALL_PARAMS, HQC_128, HQCKEM
from hqc import gf2x, gf256, reed_muller
from hqc.code import ConcatenatedCode
from hqc.reed_solomon import ReedSolomon


class TestParams(unittest.TestCase):
    def test_sizes_match_spec(self):
        expected = {  # (pk, sk, ct) byte theo đặc tả HQC
            "HQC-128": (2249, 2305, 4433),
            "HQC-192": (4522, 4586, 8978),
            "HQC-256": (7245, 7317, 14421),
        }
        for name, p in ALL_PARAMS.items():
            self.assertEqual((p.pk_bytes, p.sk_bytes, p.ct_bytes), expected[name], name)

    def test_structure(self):
        for p in ALL_PARAMS.values():
            self.assertEqual(p.n1 - p.k, 2 * p.delta)
            self.assertLessEqual(p.n1n2, p.n)
            # 2 là phần tử nguyên thủy mod n  <=>  X^n - 1 = (X - 1) * Phi(X), Phi bất khả quy
            order = 1
            x = 2
            while x != 1:
                x = x * 2 % p.n
                order += 1
            self.assertEqual(order, p.n - 1, p.name)


class TestGF2X(unittest.TestCase):
    def test_rotate_and_mul(self):
        n = 11
        self.assertEqual(gf2x.rotate(0b1, 3, n), 0b1000)
        self.assertEqual(gf2x.rotate(1 << 10, 1, n), 1)       # X^10 * X = X^11 = 1
        # (1 + X^2)(X + X^3) = X + X^5  trong F2[X]/(X^11 - 1)
        self.assertEqual(gf2x.mul(0b101, 0b1010, n), 0b100010)

    def test_mul_commutative(self):
        n = 101
        for _ in range(20):
            a, b = random.getrandbits(n), random.getrandbits(n)
            self.assertEqual(gf2x.mul(a, b, n), gf2x.mul(b, a, n))


class TestGF256(unittest.TestCase):
    def test_inverse(self):
        for a in range(1, 256):
            self.assertEqual(gf256.mul(a, gf256.inv(a)), 1)


class TestReedMuller(unittest.TestCase):
    def test_roundtrip_with_errors(self):
        for mult in (3, 5):
            n2 = 128 * mult
            max_err = (64 * mult - 1) // 2   # khoảng cách tối thiểu 64*mult
            for sym in range(256):
                cw = reed_muller.encode(sym, mult)
                noise = gf2x.from_support(random.sample(range(n2), max_err))
                self.assertEqual(reed_muller.decode(cw ^ noise, mult), sym)


class TestReedSolomon(unittest.TestCase):
    def test_corrects_up_to_delta(self):
        for p in ALL_PARAMS.values():
            rs = ReedSolomon(p.n1, p.k)
            for nerr in (0, 1, p.delta // 2, p.delta):
                msg = secrets.token_bytes(p.k)
                cw = rs.encode(msg)
                for pos in random.sample(range(p.n1), nerr):
                    cw[pos] ^= random.randrange(1, 256)
                decoded, ok = rs.decode(cw)
                self.assertTrue(ok, f"{p.name} nerr={nerr}")
                self.assertEqual(decoded, msg)

    def test_detects_too_many_errors(self):
        rs = ReedSolomon(HQC_128.n1, HQC_128.k)
        msg = secrets.token_bytes(HQC_128.k)
        cw = rs.encode(msg)
        for pos in random.sample(range(HQC_128.n1), HQC_128.delta + 5):
            cw[pos] ^= random.randrange(1, 256)
        decoded, ok = rs.decode(cw)
        self.assertFalse(ok and decoded == msg)


class TestConcatenatedCode(unittest.TestCase):
    def test_roundtrip_with_hqc_like_noise(self):
        p = HQC_128
        code = ConcatenatedCode(p)
        msg = secrets.token_bytes(p.k)
        # nhiễu trọng số lớn hơn nhiều so với trọng số thực tế của e' trong HQC
        noise = gf2x.from_support(random.sample(range(p.n1n2), 3000))
        decoded, ok = code.decode(code.encode(msg) ^ noise)
        self.assertTrue(ok)
        self.assertEqual(decoded, msg)


class TestKEM(unittest.TestCase):
    def test_roundtrip_all_levels(self):
        for p in ALL_PARAMS.values():
            kem = HQCKEM(p)
            pk, sk = kem.keygen()
            self.assertEqual(len(pk), p.pk_bytes)
            self.assertEqual(len(sk), p.sk_bytes)
            ct, ss = kem.encaps(pk)
            self.assertEqual(len(ct), p.ct_bytes)
            self.assertEqual(len(ss), p.SS_BYTES)
            self.assertEqual(kem.decaps(sk, ct), ss, p.name)

    def test_many_roundtrips_hqc128(self):
        kem = HQCKEM(HQC_128)
        pk, sk = kem.keygen()
        for _ in range(10):
            ct, ss = kem.encaps(pk)
            self.assertEqual(kem.decaps(sk, ct), ss)

    def test_deterministic(self):
        kem = HQCKEM(HQC_128)
        self.assertEqual(kem.keygen(b"seed"), kem.keygen(b"seed"))
        pk, _ = kem.keygen(b"seed")
        m, salt = bytes(16), bytes(16)
        self.assertEqual(kem.encaps(pk, m, salt), kem.encaps(pk, m, salt))

    def test_implicit_rejection(self):
        kem = HQCKEM(HQC_128)
        pk, sk = kem.keygen()
        ct, ss = kem.encaps(pk)
        for idx in (0, len(ct) // 2, len(ct) - 1):   # lật bit trong u, v và salt
            tampered = bytearray(ct)
            tampered[idx] ^= 0x01
            ss_bad = kem.decaps(sk, bytes(tampered))
            self.assertNotEqual(ss_bad, ss)
            self.assertEqual(ss_bad, kem.decaps(sk, bytes(tampered)))  # tất định

    def test_wrong_secret_key(self):
        kem = HQCKEM(HQC_128)
        pk, _ = kem.keygen()
        _, sk_other = kem.keygen()
        ct, ss = kem.encaps(pk)
        self.assertNotEqual(kem.decaps(sk_other, ct), ss)


if __name__ == "__main__":
    unittest.main()
