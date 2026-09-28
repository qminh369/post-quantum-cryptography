"""Số học trong vành R = F2[X]/(X^n - 1).

Mỗi phần tử được biểu diễn bằng một số nguyên Python: bit thứ i là hệ số của X^i.
Phép cộng là XOR; nhân với X^i là xoay vòng i bit.
"""


def rotate(a: int, i: int, n: int) -> int:
    """Nhân a với X^i trong R (xoay vòng trái i bit trên n bit)."""
    i %= n
    if i == 0:
        return a
    mask = (1 << n) - 1
    return ((a << i) | (a >> (n - i))) & mask


def mul_sparse(dense: int, support: list[int], n: int) -> int:
    """Nhân một vector bất kỳ với vector thưa (cho bởi tập vị trí bit 1).

    Mọi phép nhân trong HQC đều có ít nhất một thừa số thưa (x, y, r1, r2),
    nên chỉ cần w phép xoay + XOR: độ phức tạp O(w * n / 64).
    """
    mask = (1 << n) - 1
    res = 0
    for i in support:
        if i:
            res ^= ((dense << i) | (dense >> (n - i))) & mask
        else:
            res ^= dense
    return res


def mul(a: int, b: int, n: int) -> int:
    """Nhân tổng quát hai phần tử của R (dùng cho kiểm thử)."""
    return mul_sparse(a, support(b, n), n)


def support(a: int, n: int) -> list[int]:
    """Danh sách vị trí các bit 1."""
    return [i for i in range(n) if (a >> i) & 1]


def from_support(positions: list[int]) -> int:
    v = 0
    for i in positions:
        v |= 1 << i
    return v


def weight(a: int) -> int:
    """Trọng số Hamming."""
    return a.bit_count()


def to_bytes(a: int, nbytes: int) -> bytes:
    return a.to_bytes(nbytes, "little")


def from_bytes(data: bytes, nbits: int) -> int:
    return int.from_bytes(data, "little") & ((1 << nbits) - 1)
