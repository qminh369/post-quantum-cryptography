"""Mã ghép C = RS (mã ngoài) ∘ RM nhân bản (mã trong) – mã công khai của HQC.

    m (k byte) --RS--> n1 byte --RM--> n1 * n2 bit

Ký hiệu RS thứ i chiếm các bit [i*n2, (i+1)*n2) của mã từ.
"""

from . import reed_muller as rm
from .params import HQCParams
from .reed_solomon import ReedSolomon


class ConcatenatedCode:
    def __init__(self, params: HQCParams):
        self.p = params
        self.rs = ReedSolomon(params.n1, params.k)
        self.mult = params.rm_mult

    def encode(self, msg: bytes) -> int:
        symbols = self.rs.encode(msg)
        out = 0
        for i, sym in enumerate(symbols):
            out |= rm.encode(sym, self.mult) << (i * self.p.n2)
        return out

    def decode(self, word: int) -> tuple[bytes, bool]:
        mask = (1 << self.p.n2) - 1
        symbols = [rm.decode((word >> (i * self.p.n2)) & mask, self.mult)
                   for i in range(self.p.n1)]
        return self.rs.decode(symbols)
