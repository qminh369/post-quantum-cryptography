"""Bộ tham số HQC (theo đặc tả HQC Round 4)."""

from dataclasses import dataclass


@dataclass(frozen=True)
class HQCParams:
    name: str
    n: int        # độ dài vành R = F2[X]/(X^n - 1), n nguyên tố, 2 nguyên thủy mod n
    n1: int       # độ dài mã Reed-Solomon (số ký hiệu byte)
    n2: int       # độ dài mã Reed-Muller nhân bản (bit) cho mỗi ký hiệu RS
    k: int        # độ dài thông điệp (byte) = số chiều mã RS
    delta: int    # số lỗi ký hiệu mã RS sửa được, n1 - k = 2*delta
    w: int        # trọng số khóa bí mật x, y
    wr: int       # trọng số r1, r2
    we: int       # trọng số e
    security: int  # mức an toàn (bit)

    # --- Kích thước suy ra (byte) ---
    SEED_BYTES = 40
    SALT_BYTES = 16
    SS_BYTES = 32

    @property
    def rm_mult(self) -> int:
        """Số lần nhân bản mã RM(1,7) độ dài 128."""
        return self.n2 // 128

    @property
    def n1n2(self) -> int:
        return self.n1 * self.n2

    @property
    def vec_n_bytes(self) -> int:
        return (self.n + 7) // 8

    @property
    def vec_n1n2_bytes(self) -> int:
        return (self.n1n2 + 7) // 8

    @property
    def pk_bytes(self) -> int:
        return self.SEED_BYTES + self.vec_n_bytes

    @property
    def sk_bytes(self) -> int:
        return self.SEED_BYTES + self.k + self.pk_bytes

    @property
    def ct_bytes(self) -> int:
        return self.vec_n_bytes + self.vec_n1n2_bytes + self.SALT_BYTES


HQC_128 = HQCParams("HQC-128", n=17669, n1=46, n2=384, k=16, delta=15,
                    w=66, wr=75, we=75, security=128)
HQC_192 = HQCParams("HQC-192", n=35851, n1=56, n2=640, k=24, delta=16,
                    w=100, wr=114, we=114, security=192)
HQC_256 = HQCParams("HQC-256", n=57637, n1=90, n2=640, k=32, delta=29,
                    w=131, wr=149, we=149, security=256)

ALL_PARAMS = {p.name: p for p in (HQC_128, HQC_192, HQC_256)}
