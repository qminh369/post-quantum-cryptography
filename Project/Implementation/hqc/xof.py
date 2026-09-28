"""Sinh ngẫu nhiên tất định từ seed (dựa trên SHAKE256) và lấy mẫu vector.

- `XOF`: luồng byte giả ngẫu nhiên SHAKE256(domain || seed || counter).
- `sample_dense`: vector n bit ngẫu nhiên đều (dùng cho h).
- `sample_fixed_weight`: vector n bit có đúng w bit 1 (dùng cho x, y, r1, r2, e),
  lấy mẫu đều bằng thuật toán Floyd.

Lưu ý: rejection sampling ở đây KHÔNG chạy thời gian hằng. Cài đặt thật phải
dùng thuật toán constant-time (đây từng là nguồn tấn công timing lên HQC).
"""

import hashlib

# Tách miền (domain separation) cho từng mục đích sử dụng SHAKE256
DOMAIN_SK = b"\x01"
DOMAIN_PK = b"\x02"
DOMAIN_ENC = b"\x03"
DOMAIN_G = b"\x04"
DOMAIN_K = b"\x05"
DOMAIN_H = b"\x06"

_BLOCK = 1024


def shake(domain: bytes, *parts: bytes, outlen: int) -> bytes:
    h = hashlib.shake_256(domain)
    for part in parts:
        h.update(part)
    return h.digest(outlen)


class XOF:
    def __init__(self, seed: bytes, domain: bytes):
        self._prefix = domain + seed
        self._counter = 0
        self._buf = b""
        self._pos = 0

    def read(self, nbytes: int) -> bytes:
        while len(self._buf) - self._pos < nbytes:
            block = hashlib.shake_256(
                self._prefix + self._counter.to_bytes(4, "little")).digest(_BLOCK)
            self._buf = self._buf[self._pos:] + block
            self._pos = 0
            self._counter += 1
        out = self._buf[self._pos:self._pos + nbytes]
        self._pos += nbytes
        return out

    def uniform(self, bound: int) -> int:
        """Số nguyên đều trong [0, bound) bằng rejection sampling trên 32 bit."""
        limit = (1 << 32) - ((1 << 32) % bound)
        while True:
            r = int.from_bytes(self.read(4), "little")
            if r < limit:
                return r % bound


def sample_dense(xof: XOF, n: int) -> int:
    nbytes = (n + 7) // 8
    return int.from_bytes(xof.read(nbytes), "little") & ((1 << n) - 1)


def sample_fixed_weight(xof: XOF, n: int, w: int) -> list[int]:
    """Trả về danh sách w vị trí phân biệt, chọn đều trong [0, n)."""
    chosen: set[int] = set()
    support = []
    for j in range(n - w, n):
        t = xof.uniform(j + 1)
        pos = j if t in chosen else t
        chosen.add(pos)
        support.append(pos)
    return support
