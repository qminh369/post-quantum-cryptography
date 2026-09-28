"""HQC.PKE – lược đồ mã hóa khóa công khai (an toàn IND-CPA).

    KeyGen:  h <- đều,  x, y thưa (trọng số w),  s = x + h*y
             pk = (h, s),  sk = (x, y)
    Encrypt: r1, r2 (trọng số wr), e (trọng số we)
             u = r1 + h*r2
             v = trunc(m*G + s*r2 + e, n1*n2)
    Decrypt: m = C.decode(v - trunc(u*y, n1*n2))

Mọi tính ngẫu nhiên đều sinh từ seed để có thể mã hóa lại tất định (cần cho
biến đổi Fujisaki-Okamoto ở tầng KEM).
"""

from dataclasses import dataclass

from . import gf2x
from .code import ConcatenatedCode
from .params import HQCParams
from .xof import DOMAIN_ENC, DOMAIN_PK, DOMAIN_SK, XOF, sample_dense, sample_fixed_weight


@dataclass
class PublicKey:
    seed_pk: bytes
    h: int
    s: int


@dataclass
class SecretKey:
    seed_sk: bytes
    x: list[int]    # tập vị trí bit 1 của x
    y: list[int]    # tập vị trí bit 1 của y


@dataclass
class Ciphertext:
    u: int
    v: int


class HQCPKE:
    def __init__(self, params: HQCParams):
        self.p = params
        self.code = ConcatenatedCode(params)

    # ---------------------------------------------------------------- keygen
    def expand_h(self, seed_pk: bytes) -> int:
        return sample_dense(XOF(seed_pk, DOMAIN_PK), self.p.n)

    def expand_sk(self, seed_sk: bytes) -> SecretKey:
        xof = XOF(seed_sk, DOMAIN_SK)
        y = sample_fixed_weight(xof, self.p.n, self.p.w)
        x = sample_fixed_weight(xof, self.p.n, self.p.w)
        return SecretKey(seed_sk, x, y)

    def keygen(self, seed_sk: bytes, seed_pk: bytes) -> tuple[PublicKey, SecretKey]:
        n = self.p.n
        sk = self.expand_sk(seed_sk)
        h = self.expand_h(seed_pk)
        s = gf2x.from_support(sk.x) ^ gf2x.mul_sparse(h, sk.y, n)
        return PublicKey(seed_pk, h, s), sk

    # --------------------------------------------------------------- encrypt
    def encrypt(self, pk: PublicKey, m: bytes, theta: bytes) -> Ciphertext:
        p = self.p
        xof = XOF(theta, DOMAIN_ENC)
        r2 = sample_fixed_weight(xof, p.n, p.wr)
        e = sample_fixed_weight(xof, p.n, p.we)
        r1 = sample_fixed_weight(xof, p.n, p.wr)

        u = gf2x.from_support(r1) ^ gf2x.mul_sparse(pk.h, r2, p.n)
        trunc = (1 << p.n1n2) - 1
        v = (self.code.encode(m) ^ gf2x.mul_sparse(pk.s, r2, p.n) ^ gf2x.from_support(e)) & trunc
        return Ciphertext(u, v)

    # --------------------------------------------------------------- decrypt
    def decrypt(self, sk: SecretKey, ct: Ciphertext) -> tuple[bytes, bool]:
        p = self.p
        trunc = (1 << p.n1n2) - 1
        noisy = ct.v ^ (gf2x.mul_sparse(ct.u, sk.y, p.n) & trunc)   # = mG + e'
        return self.code.decode(noisy)

    # ------------------------------------------------------- serialization
    def pk_to_bytes(self, pk: PublicKey) -> bytes:
        return pk.seed_pk + gf2x.to_bytes(pk.s, self.p.vec_n_bytes)

    def pk_from_bytes(self, data: bytes) -> PublicKey:
        if len(data) != self.p.pk_bytes:
            raise ValueError("Độ dài khóa công khai không hợp lệ")
        seed_pk = data[: self.p.SEED_BYTES]
        s = gf2x.from_bytes(data[self.p.SEED_BYTES:], self.p.n)
        return PublicKey(seed_pk, self.expand_h(seed_pk), s)

    def ct_to_bytes(self, ct: Ciphertext) -> bytes:
        return (gf2x.to_bytes(ct.u, self.p.vec_n_bytes)
                + gf2x.to_bytes(ct.v, self.p.vec_n1n2_bytes))

    def ct_from_bytes(self, data: bytes) -> Ciphertext:
        nu = self.p.vec_n_bytes
        return Ciphertext(gf2x.from_bytes(data[:nu], self.p.n),
                          gf2x.from_bytes(data[nu:], self.p.n1n2))
