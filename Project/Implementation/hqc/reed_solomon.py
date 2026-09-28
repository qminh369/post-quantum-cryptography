"""Mã Reed-Solomon rút gọn [n1, k, 2*delta + 1] trên GF(256) – mã ngoài của HQC.

- Đa thức sinh g(x) = (x - a^1)(x - a^2)...(x - a^{2*delta}).
- Mã hóa hệ thống: codeword = [parity (2*delta byte) | message (k byte)].
- Giải mã: hội chứng -> Berlekamp-Massey -> tìm nghiệm Chien -> giá trị lỗi Forney.

Lưu ý: bản cài đặt học tập, KHÔNG chạy thời gian hằng.
"""

from . import gf256 as gf


class ReedSolomon:
    def __init__(self, n1: int, k: int):
        if n1 > 255 or k >= n1 or (n1 - k) % 2:
            raise ValueError("Tham số Reed-Solomon không hợp lệ")
        self.n1 = n1
        self.k = k
        self.nroots = n1 - k          # = 2*delta
        self.delta = self.nroots // 2
        self.gen = self._generator_poly()

    def _generator_poly(self) -> list[int]:
        g = [1]
        for i in range(1, self.nroots + 1):
            root = gf.alpha_pow(i)
            # g(x) <- g(x) * (x + root)
            new = [0] * (len(g) + 1)
            for j, coef in enumerate(g):
                new[j] ^= gf.mul(coef, root)
                new[j + 1] ^= coef
            g = new
        return g  # hệ số bậc thấp trước, bậc nroots, monic

    # ------------------------------------------------------------------ encode
    def encode(self, msg: bytes) -> list[int]:
        if len(msg) != self.k:
            raise ValueError(f"Thông điệp phải dài {self.k} byte")
        # Tính phần dư của x^{nroots} * m(x) chia g(x) bằng thanh ghi LFSR.
        parity = [0] * self.nroots
        for byte in reversed(msg):                # đưa hệ số bậc cao vào trước
            feedback = byte ^ parity[-1]
            for j in range(self.nroots - 1, 0, -1):
                parity[j] = parity[j - 1] ^ gf.mul(feedback, self.gen[j])
            parity[0] = gf.mul(feedback, self.gen[0])
        return parity + list(msg)

    # ------------------------------------------------------------------ decode
    def syndromes(self, word: list[int]) -> list[int]:
        return [gf.poly_eval(word, gf.alpha_pow(j)) for j in range(1, self.nroots + 1)]

    @staticmethod
    def _berlekamp_massey(synd: list[int]) -> list[int]:
        C = [1]      # đa thức định vị lỗi Lambda(x)
        B = [1]
        L, m, b = 0, 1, 1
        for idx in range(len(synd)):
            d = synd[idx]
            for i in range(1, L + 1):
                if i < len(C):
                    d ^= gf.mul(C[i], synd[idx - i])
            if d == 0:
                m += 1
                continue
            coef = gf.div(d, b)
            T = C[:]
            if len(C) < len(B) + m:
                C += [0] * (len(B) + m - len(C))
            for i, bi in enumerate(B):
                C[i + m] ^= gf.mul(coef, bi)
            if 2 * L <= idx:
                L = idx + 1 - L
                B, b, m = T, d, 1
            else:
                m += 1
        return C[: L + 1]

    def decode(self, word: list[int]) -> tuple[bytes, bool]:
        """Trả về (message, thành_công). Sửa được tối đa delta ký hiệu lỗi."""
        word = list(word)
        synd = self.syndromes(word)
        if not any(synd):
            return bytes(word[self.nroots:]), True

        lam = self._berlekamp_massey(synd)
        nerr = len(lam) - 1
        if nerr > self.delta:
            return bytes(word[self.nroots:]), False

        # Chien search: vị trí i là lỗi nếu Lambda(a^{-i}) = 0
        positions = [i for i in range(self.n1) if gf.poly_eval(lam, gf.alpha_pow(-i)) == 0]
        if len(positions) != nerr:
            return bytes(word[self.nroots:]), False

        # Forney: Omega(x) = S(x) * Lambda(x) mod x^{2*delta}
        omega = [0] * self.nroots
        for i, s in enumerate(synd):
            for j, l in enumerate(lam):
                if i + j < self.nroots:
                    omega[i + j] ^= gf.mul(s, l)
        # Đạo hàm hình thức trên đặc số 2: chỉ giữ hạng bậc lẻ
        lam_deriv = [lam[i] if i % 2 == 1 else 0 for i in range(1, len(lam))]

        for i in positions:
            x_inv = gf.alpha_pow(-i)
            denom = gf.poly_eval(lam_deriv, x_inv)
            if denom == 0:
                return bytes(word[self.nroots:]), False
            word[i] ^= gf.div(gf.poly_eval(omega, x_inv), denom)

        if any(self.syndromes(word)):
            return bytes(word[self.nroots:]), False
        return bytes(word[self.nroots:]), True
