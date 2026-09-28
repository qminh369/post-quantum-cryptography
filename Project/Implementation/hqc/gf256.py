"""Trường hữu hạn GF(2^8) với đa thức nguyên thủy x^8 + x^4 + x^3 + x^2 + 1 (0x11D).

Dùng bảng log/exp: alpha = 2 (tức x) là phần tử sinh của nhóm nhân.
"""

PRIM_POLY = 0x11D

EXP = [0] * 512
LOG = [0] * 256

_x = 1
for _i in range(255):
    EXP[_i] = _x
    LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= PRIM_POLY
for _i in range(255, 512):
    EXP[_i] = EXP[_i - 255]


def add(a: int, b: int) -> int:
    return a ^ b


def mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("0 không khả nghịch trong GF(256)")
    return EXP[255 - LOG[a]]


def div(a: int, b: int) -> int:
    return mul(a, inv(b))


def alpha_pow(i: int) -> int:
    """alpha^i (i có thể âm)."""
    return EXP[i % 255]


def poly_eval(poly: list[int], x: int) -> int:
    """Tính giá trị đa thức (hệ số bậc thấp trước) tại x theo Horner."""
    res = 0
    for coef in reversed(poly):
        res = mul(res, x) ^ coef
    return res
