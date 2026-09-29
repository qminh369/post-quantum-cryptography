"""
HQC CƠ BẢN – phiên bản đơn giản nhất cho người mới bắt đầu
==========================================================

Mục tiêu: hiểu Ý TƯỞNG của HQC chỉ trong một file, không cần kiến thức sâu.

Đơn giản hóa so với HQC thật (thư mục hqc/):
  - Vector được lưu bằng list các bit 0/1 (dễ in ra, dễ nhìn).
  - Tham số nhỏ: n = 1019 thay vì 17669.
  - Mã sửa lỗi là MÃ LẶP (lặp mỗi bit 31 lần, giải mã theo đa số)
    thay vì Reed-Muller + Reed-Solomon.
  - Dùng module `random` cho dễ đọc.

=> CHỈ ĐỂ HỌC, HOÀN TOÀN KHÔNG AN TOÀN.

Chạy:  python hqc_basic.py
"""

import hashlib
import random

# =============================================================================
# 1. THAM SỐ
# =============================================================================
N = 1019        # độ dài vector (số nguyên tố, 2 là phần tử nguyên thủy mod N)
K = 32          # số bit của thông điệp
REP = 31        # mã lặp: mỗi bit thông điệp được lặp lại REP lần
W = 7           # số bit 1 trong khóa bí mật x, y
WR = 7          # số bit 1 trong nhiễu r1, r2
WE = 7          # số bit 1 trong nhiễu e

CODE_LEN = K * REP      # = 992 bit, độ dài mã từ (<= N)


# =============================================================================
# 2. CÁC PHÉP TOÁN TRÊN VECTOR BIT
# =============================================================================
def random_dense():
    """Vector ngẫu nhiên N bit (khoảng một nửa là bit 1)."""
    return [random.randint(0, 1) for _ in range(N)]


def random_sparse(weight):
    """Vector N bit có đúng `weight` bit 1 ở các vị trí ngẫu nhiên (vector THƯA)."""
    v = [0] * N
    for pos in random.sample(range(N), weight):
        v[pos] = 1
    return v


def add(a, b):
    """Cộng hai vector = XOR từng bit (trong hệ nhị phân: 1 + 1 = 0)."""
    return [x ^ y for x, y in zip(a, b)]


def rotate(a, k):
    """Xoay vòng vector sang phải k vị trí.

    Ví dụ (N = 5):  rotate([1,1,0,0,0], 2) = [0,0,1,1,0]
    Trong HQC, 'nhân với X^k' chính là xoay vòng k vị trí.
    """
    k %= len(a)
    return a[-k:] + a[:-k] if k else a[:]


def multiply(a, b):
    """Nhân hai vector trong vành đa thức vòng.

    Ý tưởng: a * b = tổng (XOR) của các bản xoay của a,
             mỗi bản xoay ứng với một bit 1 của b.
    Nếu b thưa (ít bit 1) thì phép nhân rất nhanh.
    """
    result = [0] * N
    for k in range(N):
        if b[k] == 1:
            result = add(result, rotate(a, k))
    return result


def weight(v):
    """Trọng số Hamming = số bit 1."""
    return sum(v)


# =============================================================================
# 3. MÃ SỬA LỖI: MÃ LẶP
# =============================================================================
def encode(message_bits):
    """Mã hóa: lặp mỗi bit REP lần.   [1, 0] -> [1,1,...,1, 0,0,...,0]"""
    codeword = []
    for bit in message_bits:
        codeword += [bit] * REP
    return codeword + [0] * (N - CODE_LEN)          # đệm cho đủ N bit


def decode(noisy_bits):
    """Giải mã: mỗi nhóm REP bit, bit nào xuất hiện nhiều hơn thì chọn bit đó."""
    message = []
    for i in range(K):
        group = noisy_bits[i * REP:(i + 1) * REP]
        message.append(1 if sum(group) > REP // 2 else 0)
    return message


# =============================================================================
# 4. HQC – MÃ HÓA KHÓA CÔNG KHAI
# =============================================================================
def keygen():
    """Alice tạo khóa.

        h     : ngẫu nhiên (dày)          -> công khai
        x, y  : thưa                      -> BÍ MẬT
        s     = x + h*y                   -> công khai
    """
    h = random_dense()
    x = random_sparse(W)
    y = random_sparse(W)
    s = add(x, multiply(h, y))
    public_key = (h, s)
    secret_key = y                       # để giải mã chỉ cần y
    return public_key, secret_key


def encrypt(public_key, message_bits, rng=random):
    """Bob mã hóa thông điệp bằng khóa công khai của Alice.

        r1, r2, e : nhiễu thưa, dùng một lần
        u = r1 + h*r2
        v = encode(m) + s*r2 + e
    """
    h, s = public_key
    r1 = _sparse_from(rng, WR)
    r2 = _sparse_from(rng, WR)
    e = _sparse_from(rng, WE)

    u = add(r1, multiply(h, r2))
    v = add(add(encode(message_bits), multiply(s, r2)), e)
    return u, v


def decrypt(secret_key, ciphertext):
    """Alice giải mã.

        v - u*y = encode(m) + (x*r2 + r1*y + e)
                             └──── nhiễu nhỏ ───┘
    Phần dày h*y*r2 bị triệt tiêu, chỉ còn nhiễu nhỏ -> mã lặp sửa được.
    """
    y = secret_key
    u, v = ciphertext
    noisy = add(v, multiply(u, y))       # trên nhị phân: trừ = cộng
    return decode(noisy)


def _sparse_from(rng, weight):
    """Giống random_sparse nhưng lấy ngẫu nhiên từ `rng` (cần cho phần KEM)."""
    v = [0] * N
    for pos in rng.sample(range(N), weight):
        v[pos] = 1
    return v


# =============================================================================
# 5. HQC-KEM – TRAO ĐỔI KHÓA (tùy chọn, đọc sau khi hiểu phần 4)
# =============================================================================
def _hash(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(bytes(p))
    return h.digest()


def encaps(public_key):
    """Bob: tạo khóa chung + bản mã.

    Nhiễu được tính TỪ m (qua hàm băm) để Alice có thể mã hóa lại và kiểm tra.
    """
    h, s = public_key
    m = [random.randint(0, 1) for _ in range(K)]              # bí mật ngẫu nhiên
    rng = random.Random(_hash(h, s, m))                       # nhiễu phụ thuộc m
    u, v = encrypt(public_key, m, rng)
    shared_key = _hash(m, u, v)                               # khóa chung
    return (u, v), shared_key


def decaps(public_key, secret_key, sigma, ciphertext):
    """Alice: lấy lại khóa chung.

    Giải mã -> mã hóa lại -> nếu khớp: khóa thật, nếu không: khóa rác (từ chối ngầm).
    """
    h, s = public_key
    u, v = ciphertext
    m = decrypt(secret_key, ciphertext)
    rng = random.Random(_hash(h, s, m))
    if encrypt(public_key, m, rng) == (u, v):
        return _hash(m, u, v)                                 # hợp lệ
    return _hash(sigma, u, v)                                 # bản mã giả -> khóa rác


# =============================================================================
# 6. DEMO
# =============================================================================
def show(v, length=60):
    """In gọn một vector."""
    return "".join(map(str, v[:length])) + ("..." if len(v) > length else "")


def demo_pke():
    print("=" * 70)
    print("PHẦN A – MÃ HÓA / GIẢI MÃ MỘT THÔNG ĐIỆP")
    print("=" * 70)
    print(f"Tham số: N={N}, K={K} bit, mã lặp x{REP}, W=WR=WE={W}\n")

    # --- Alice tạo khóa ---
    public_key, y = keygen()
    h, s = public_key
    print("[1] Alice tạo khóa")
    print(f"    h (công khai, dày) : {show(h)}  trọng số = {weight(h)}")
    print(f"    y (BÍ MẬT, thưa)   : bit 1 tại vị trí {[i for i in range(N) if y[i]]}")
    print(f"    s = x + h*y        : {show(s)}  trọng số = {weight(s)}")
    print("    -> s trông ngẫu nhiên, không nhìn ra x, y\n")

    # --- Bob mã hóa ---
    message = [random.randint(0, 1) for _ in range(K)]
    u, v = encrypt(public_key, message)
    print("[2] Bob mã hóa thông điệp")
    print(f"    m                  : {show(message)}")
    print(f"    encode(m)          : {show(encode(message))}")
    print(f"    v                  : {show(v)}")
    hidden = add(v, encode(message))
    print(f"    v XOR encode(m)    : trọng số = {weight(hidden[:CODE_LEN])}/{CODE_LEN}"
          f"  (~50% -> thông điệp bị che kín)\n")

    # --- Alice giải mã ---
    noisy = add(v, multiply(u, y))
    error = add(noisy, encode(message))
    recovered = decrypt(y, (u, v))
    print("[3] Alice giải mã")
    print(f"    v - u*y            : {show(noisy)}")
    print(f"    nhiễu còn lại e'   : trọng số = {weight(error[:CODE_LEN])}/{CODE_LEN}"
          f"  (~10% -> mã lặp sửa được)")
    print(f"    m giải mã được     : {show(recovered)}")
    print(f"    Đúng?              : {'✓' if recovered == message else '✗'}\n")

    # --- Kẻ tấn công không có y ---
    print("[4] Kẻ tấn công thử giải mã bằng khóa sai")
    _, wrong_y = keygen()
    guess = decrypt(wrong_y, (u, v))
    same = sum(a == b for a, b in zip(guess, message))
    print(f"    Đúng {same}/{K} bit  (~50% = đoán mò)\n")


def demo_kem():
    print("=" * 70)
    print("PHẦN B – TRAO ĐỔI KHÓA (KEM)")
    print("=" * 70)
    public_key, y = keygen()
    sigma = [random.randint(0, 1) for _ in range(K)]          # bí mật cho từ chối ngầm

    ct, key_bob = encaps(public_key)
    key_alice = decaps(public_key, y, sigma, ct)
    print(f"    Khóa của Bob   : {key_bob.hex()}")
    print(f"    Khóa của Alice : {key_alice.hex()}")
    print(f"    Khớp?          : {'✓' if key_alice == key_bob else '✗'}")

    u, v = ct
    fake_v = v[:]
    fake_v[0] ^= 1                                            # sửa 1 bit
    key_fake = decaps(public_key, y, sigma, (u, fake_v))
    print(f"    Sửa 1 bit bản mã -> khóa: {key_fake.hex()[:32]}...  "
          f"khớp? {'✓' if key_fake == key_bob else '✗ (bị từ chối ngầm)'}\n")


def demo_success_rate(trials=200):
    print("=" * 70)
    print(f"PHẦN C – THỬ {trials} LẦN")
    print("=" * 70)
    ok = 0
    for _ in range(trials):
        pk, y = keygen()
        m = [random.randint(0, 1) for _ in range(K)]
        ok += decrypt(y, encrypt(pk, m)) == m
    print(f"    Giải mã đúng {ok}/{trials} lần\n")


if __name__ == "__main__":
    demo_pke()
    demo_kem()
    demo_success_rate()
