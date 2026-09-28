"""Mã Reed-Muller RM(1,7) [128, 8, 64] nhân bản – mã trong của HQC.

Một byte m = (m0, m1..m7) được mã hóa thành 128 bit:
    c[j] = m0 XOR <(m1..m7), bits(j)>,  j = 0..127
rồi lặp lại `mult` lần (mult = 3 với HQC-128, 5 với HQC-192/256).

Giải mã hợp lý cực đại bằng biến đổi Hadamard nhanh (FHT).
"""

RM_LEN = 128


def _build_table() -> list[int]:
    table = []
    for m in range(256):
        m0, a = m & 1, m >> 1
        cw = 0
        for j in range(RM_LEN):
            if m0 ^ ((a & j).bit_count() & 1):
                cw |= 1 << j
        table.append(cw)
    return table


_CODEWORDS = _build_table()   # 256 mã từ 128 bit, tính sẵn


def encode_byte(m: int) -> int:
    return _CODEWORDS[m]


def encode(symbol: int, mult: int) -> int:
    """Mã hóa một byte thành mult * 128 bit (số nguyên)."""
    cw = _CODEWORDS[symbol]
    out = 0
    for t in range(mult):
        out |= cw << (t * RM_LEN)
    return out


def _fht(values: list[int]) -> list[int]:
    """Biến đổi Hadamard nhanh (không chuẩn hóa) trên 128 phần tử."""
    v = list(values)
    h = 1
    while h < RM_LEN:
        for i in range(0, RM_LEN, 2 * h):
            for j in range(i, i + h):
                x, y = v[j], v[j + h]
                v[j], v[j + h] = x + y, x - y
        h *= 2
    return v


def decode(word: int, mult: int) -> int:
    """Giải mã mult * 128 bit về một byte."""
    # F[j] = tổng qua các bản sao của (-1)^{bit}  (bit 0 -> +1, bit 1 -> -1)
    F = [mult] * RM_LEN
    for t in range(mult):
        chunk = (word >> (t * RM_LEN)) & ((1 << RM_LEN) - 1)
        for j in range(RM_LEN):
            if (chunk >> j) & 1:
                F[j] -= 2
    T = _fht(F)
    # Tìm phần tử có |T| lớn nhất; khi bằng nhau lấy chỉ số nhỏ nhất
    best_a, best_val = 0, T[0]
    for a in range(1, RM_LEN):
        if abs(T[a]) > abs(best_val):
            best_a, best_val = a, T[a]
    m0 = 1 if best_val < 0 else 0
    return (best_a << 1) | m0
