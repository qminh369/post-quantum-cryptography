# Tìm hiểu HQC – Hướng dẫn từng bước cho người mới bắt đầu

> Tài liệu học tập về **HQC (Hamming Quasi-Cyclic)** theo lối "hiểu bản chất trước, công thức sau": trực giác, ví dụ tính tay, chạy thử code, bài tập tự luyện.
>
> Đọc kèm:
> - [PQC_Overview.md](PQC_Overview.md) – tổng quan mật mã hậu lượng tử.
> - [HQC_Post_Quantum_Cryptography.md](HQC_Post_Quantum_Cryptography.md) – tài liệu nghiên cứu chuyên sâu (tham số, chứng minh an toàn, tấn công, chuẩn hóa).

---

## Mục lục

1. [HQC trong một đoạn văn](#1-hqc-trong-một-đoạn-văn)
2. [Kiến thức cần có trước](#2-kiến-thức-cần-có-trước)
3. [Trực giác: "giấu thông điệp trong nhiễu"](#3-trực-giác-giấu-thông-điệp-trong-nhiễu)
4. [Ba khái niệm nền tảng](#4-ba-khái-niệm-nền-tảng)
5. [HQC hoạt động thế nào – kể bằng câu chuyện Alice và Bob](#5-hqc-hoạt-động-thế-nào--kể-bằng-câu-chuyện-alice-và-bob)
6. [Ví dụ tính tay với n = 11](#6-ví-dụ-tính-tay-với-n--11)
7. [Vì sao kẻ tấn công không giải được?](#7-vì-sao-kẻ-tấn-công-không-giải-được)
8. [Từ mã hóa (PKE) đến đóng gói khóa (KEM)](#8-từ-mã-hóa-pke-đến-đóng-gói-khóa-kem)
9. [Chạy thử HQC thật bằng Python (liboqs)](#9-chạy-thử-hqc-thật-bằng-python-liboqs)
10. [Những hiểu lầm thường gặp](#10-những-hiểu-lầm-thường-gặp)
11. [Câu hỏi ôn tập và bài tập](#11-câu-hỏi-ôn-tập-và-bài-tập)
12. [Lộ trình học tiếp](#12-lộ-trình-học-tiếp)

---

## 1. HQC trong một đoạn văn

**HQC** là một **cơ chế đóng gói khóa (KEM)** giúp hai bên thiết lập một khóa bí mật chung qua kênh công khai, thay cho ECDH/RSA vốn sẽ bị máy tính lượng tử phá. HQC thuộc họ **mật mã dựa trên mã sửa lỗi**: người gửi **cố tình thêm lỗi (nhiễu)** vào dữ liệu; chỉ người có khóa bí mật mới **giảm được nhiễu đủ nhỏ** để một bộ giải mã sửa lỗi khôi phục thông điệp. Ngày **11/03/2025**, NIST chọn HQC làm **KEM dự phòng** cho ML-KEM (Kyber), để thế giới có một phương án không dựa trên bài toán lưới.

---

## 2. Kiến thức cần có trước

| Chủ đề | Mức cần biết | Tự kiểm tra |
|---|---|---|
| Phép XOR, số nhị phân | Thành thạo | `1011 ⊕ 0110 = ?` (đáp án: `1101`) |
| Đại số tuyến tính trên F₂ | Vector, ma trận, nhân ma trận mod 2 | Biết rằng trong F₂: `1 + 1 = 0`, trừ = cộng |
| Đa thức | Cộng, nhân đa thức | Nhân `(1 + X)(1 + X)` trên F₂ = `1 + X²` |
| Mã sửa lỗi cơ bản | Ý tưởng mã lặp, khoảng cách Hamming | Mã lặp 3 lần sửa được bao nhiêu lỗi? (1) |
| Mật mã khóa công khai | Khóa công khai/bí mật, KEM | Phân biệt được mã hóa và trao đổi khóa |

> Nếu chưa vững phần mã sửa lỗi, hãy đọc mục 4 thật kỹ trước khi đi tiếp.

---

## 3. Trực giác: "giấu thông điệp trong nhiễu"

Hãy tưởng tượng:

1. Alice công bố một "ổ khóa" trông **hoàn toàn ngẫu nhiên**, nhưng bên trong có cài một **bí mật nhỏ** mà chỉ cô biết.
2. Bob muốn gửi thông điệp. Anh **mã hóa thông điệp bằng mã sửa lỗi** (thêm dư thừa), rồi **trộn với ổ khóa của Alice và một ít nhiễu ngẫu nhiên**.
3. Với người ngoài, kết quả trông như **rác ngẫu nhiên** – lượng nhiễu quá lớn để giải mã.
4. Alice dùng bí mật của mình để **triệt tiêu phần lớn nhiễu**. Phần nhiễu **còn lại đủ nhỏ** để mã sửa lỗi xử lý → Alice đọc được thông điệp.

**Điểm tinh tế**: bí mật và nhiễu đều là các vector **thưa** (rất ít bit 1). Tích của hai vector thưa vẫn **tương đối thưa** → nhiễu còn sót lại sau khi Alice "gỡ khóa" là nhỏ. Còn kẻ tấn công không có bí mật thì phải đối mặt với nhiễu **dày đặc** không sửa nổi.

---

## 4. Ba khái niệm nền tảng

### 4.1. Trọng số Hamming – "độ thưa" của vector

**Trọng số Hamming** `w(v)` = số bit 1 trong v.

```
v = 0010000100   →  w(v) = 2   (thưa)
u = 1101101011   →  w(u) = 7   (dày)
```

Trong HQC, **khóa bí mật và nhiễu là vector thưa**: ví dụ HQC-128 có vector dài **17 669 bit** nhưng chỉ có **66–75 bit 1**.

### 4.2. Mã sửa lỗi – thêm dư thừa để chịu được lỗi

Ví dụ đơn giản nhất: **mã lặp (repetition code)**. Lặp mỗi bit 5 lần:

```
Mã hóa:   1  →  11111
Kênh gây 2 lỗi:  11111 → 10110
Giải mã theo đa số: có 3 bit 1 > 2 bit 0  →  1  ✓
```

Mã lặp độ dài `N` sửa được tối đa `⌊(N−1)/2⌋` lỗi.

HQC thật dùng mã mạnh hơn nhiều: **Reed-Muller ghép Reed-Solomon**, nhưng ý tưởng giống hệt: *mã hóa → chịu lỗi → giải mã*. Mã này **công khai**, ai cũng biết – bí mật không nằm ở đây.

### 4.3. Vành đa thức vòng – phép nhân là "xoay vòng"

HQC làm việc trong vành `R = F₂[X] / (Xⁿ − 1)`. Nghe đáng sợ, nhưng thực chất:

- Mỗi vector n bit ↔ một đa thức. Ví dụ với n = 5: `10100` ↔ `1 + X²`.
- Vì `Xⁿ = 1`, **nhân với Xᵏ = xoay vòng vector sang phải k vị trí**:

```
n = 5,  v = 1 + X² = 10100
X · v  = X + X³     = 01010   (xoay phải 1)
X³ · v = X³ + X⁵ = X³ + 1 = 10010   (xoay phải 3, X⁵ quay về X⁰)
```

- Nhân với đa thức nhiều hạng = **XOR của nhiều bản xoay**.

**Vì sao dùng cấu trúc vòng?** Khóa chỉ cần lưu **một vector n bit** thay vì cả ma trận n × n → khóa nhỏ hơn hàng nghìn lần. Đó là chữ **"Quasi-Cyclic"** trong tên HQC; còn **"Hamming"** chỉ việc đo lỗi bằng trọng số Hamming.

---

## 5. HQC hoạt động thế nào – kể bằng câu chuyện Alice và Bob

Ký hiệu: chữ in thường là phần tử của R (vector n bit). "thưa" = trọng số nhỏ. Mọi phép `+` là XOR.

### Bước 1 – Alice tạo khóa (KeyGen)

```
h      ← ngẫu nhiên (dày)
x, y   ← ngẫu nhiên THƯA              ← khóa bí mật
s      = x + h·y
Khóa công khai: (h, s)
```

> 🔑 `s` trông ngẫu nhiên vì `h·y` là vector dày. Tìm lại `(x, y)` từ `(h, s)` chính là **bài toán khó QCSD**.

### Bước 2 – Bob mã hóa thông điệp m (Encrypt)

```
r₁, r₂, e ← ngẫu nhiên THƯA          ← nhiễu dùng một lần
u = r₁ + h·r₂
v = m·G + s·r₂ + e                   (m·G: thông điệp đã mã hóa bằng mã sửa lỗi)
Gửi bản mã: (u, v)
```

> Phần `s·r₂` là **dày** → che hoàn toàn `m·G`.

### Bước 3 – Alice giải mã (Decrypt)

Alice tính `v − u·y` (trên F₂, trừ = cộng):

```
v − u·y = m·G + s·r₂ + e − (r₁ + h·r₂)·y
        = m·G + (x + h·y)·r₂ + e − r₁·y − h·r₂·y
        = m·G + x·r₂ + h·y·r₂ + e − r₁·y − h·r₂·y
        = m·G + x·r₂ − r₁·y + e            ← hai hạng h·y·r₂ triệt tiêu!
                └──── e' (THƯA) ────┘
```

Vì `x, y, r₁, r₂, e` đều thưa nên `e'` cũng **tương đối thưa** → Alice chạy bộ giải mã của mã sửa lỗi, thu lại `m`. 🎉

### Sơ đồ tóm tắt

```
        ALICE                                        BOB
  ┌───────────────────┐                     
  │ h (dày), x,y (thưa)│
  │ s = x + h·y        │ ───── pk = (h, s) ─────▶ ┌────────────────────────┐
  └───────────────────┘                          │ r₁, r₂, e (thưa)        │
                                                 │ u = r₁ + h·r₂           │
  ┌───────────────────┐ ◀──── ct = (u, v) ────── │ v = mG + s·r₂ + e       │
  │ v − u·y            │                          └────────────────────────┘
  │ = mG + e' (e' thưa)│
  │ Decode → m         │
  └───────────────────┘
```

**Nhận xét**: So với Ring-LWE (nền tảng của Kyber), cấu trúc gần như y hệt – chỉ khác "nhiễu nhỏ" được đo bằng **trọng số Hamming** thay vì **độ lớn số học**, và khử nhiễu bằng **mã sửa lỗi** thay vì **làm tròn**.

---

## 6. Ví dụ tính tay với n = 11

> Tham số đồ chơi để tính bằng tay. **Hoàn toàn không an toàn**, chỉ để hiểu cơ chế.

**Thiết lập**
- `n = 11` (11 là số nguyên tố và 2 là phần tử nguyên thủy mod 11 – đúng điều kiện HQC yêu cầu).
- Thông điệp 1 bit, mã công khai là **mã lặp độ dài 11**: `m = 1 → m·G = 11111111111`. Giải mã theo đa số, sửa được tới **5 lỗi**.
- Trọng số `w = w_r = w_e = 1`.
- Ta viết vector bằng **tập vị trí các bit 1** (vị trí 0 → 10). Nhân với `Xᵏ` = cộng k vào mọi vị trí (mod 11).

### Bước 1 – KeyGen

| Đại lượng | Giá trị (vị trí bit 1) | Ghi chú |
|---|---|---|
| `h` | {0, 2, 3, 7, 9} | dày, công khai |
| `x` | {4}  (= X⁴) | bí mật |
| `y` | {1}  (= X¹) | bí mật |
| `h·y` | {1, 3, 4, 8, 10} | xoay h sang phải 1 |
| `s = x + h·y` | {4} ⊕ {1,3,4,8,10} = **{1, 3, 8, 10}** | vị trí 4 bị triệt tiêu |

Khóa công khai: `h = {0,2,3,7,9}`, `s = {1,3,8,10}`.

### Bước 2 – Bob mã hóa m = 1

Chọn nhiễu: `r₁ = {7}`, `r₂ = {2}`, `e = {9}`.

| Đại lượng | Tính toán | Kết quả |
|---|---|---|
| `h·r₂` | xoay h phải 2: {2,4,5,9,11→0} | {0, 2, 4, 5, 9} |
| `u = r₁ + h·r₂` | {7} ⊕ {0,2,4,5,9} | **{0, 2, 4, 5, 7, 9}** |
| `s·r₂` | xoay s phải 2: {3,5,10,12→1} | {1, 3, 5, 10} |
| `s·r₂ + e` | {1,3,5,10} ⊕ {9} | {1, 3, 5, 9, 10} |
| `v = m·G + s·r₂ + e` | 11111111111 lật các vị trí {1,3,5,9,10} | **{0, 2, 4, 6, 7, 8}** |

Bản mã: `u = {0,2,4,5,7,9}`, `v = {0,2,4,6,7,8}`. Nhìn `v`, kẻ tấn công thấy 6 bit 1 / 5 bit 0 → **không thể đoán m** bằng đa số!

### Bước 3 – Alice giải mã

| Đại lượng | Tính toán | Kết quả |
|---|---|---|
| `u·y` | xoay u phải 1 | {1, 3, 5, 6, 8, 10} |
| `v + u·y` | {0,2,4,6,7,8} ⊕ {1,3,5,6,8,10} | **{0, 1, 2, 3, 4, 5, 7, 10}** |

Kết quả có **8 bit 1, 3 bit 0** (lỗi tại vị trí 6, 8, 9) → đa số là 1 → **m = 1** ✓

### Kiểm tra bằng công thức
`e' = x·r₂ + r₁·y + e = X⁴·X² + X⁷·X¹ + X⁹ = X⁶ + X⁸ + X⁹` → lỗi đúng tại vị trí **{6, 8, 9}**, trọng số 3 ≤ 5 nên giải mã thành công. Khớp hoàn toàn với bảng trên.

> 💡 **Thử tự làm**: đổi `m = 0` (khi đó `m·G = 00000000000`) và lặp lại các bước – bạn sẽ thấy `v + u·y = {6, 8, 9}`, đa số là 0.

---

## 7. Vì sao kẻ tấn công không giải được?

Kẻ tấn công biết `h, s, u, v`. Họ có hai hướng:

**Hướng 1 – Tìm khóa bí mật**: từ `s = x + h·y`, tìm `(x, y)` thưa. Đây là **bài toán giải mã hội chứng quasi-cyclic (QCSD)**.
- Ở ví dụ n = 11, chỉ có 11 × 11 = 121 khả năng → vét cạn tức thì.
- Ở HQC-128: n = 17 669, mỗi vector có 66 bit 1. Số cách chọn **một** vector đã là `C(17669, 66)` – lớn hơn `2⁵⁰⁰`.
- Thuật toán tấn công tốt nhất (**Information Set Decoding – ISD**) thông minh hơn vét cạn nhiều, nhưng tham số được chọn để ISD vẫn cần khoảng **2¹²⁸ phép tính** (mức NIST 1).

**Hướng 2 – Giải mã trực tiếp bản mã**: từ `(u, v)` tìm `r₂` thưa – cũng là bài toán QCSD tương tự.

**Còn máy tính lượng tử?**
- Thuật toán **Shor không áp dụng được** – bài toán giải mã mã ngẫu nhiên không có cấu trúc chu kỳ mà Shor khai thác.
- **Grover** chỉ tăng tốc một phần bên trong ISD, đã được tính vào tham số.
- Bài toán giải mã hội chứng tổng quát là **NP-đầy đủ** và được nghiên cứu từ năm 1978 – một trong những nền tảng lâu đời nhất của PQC.

---

## 8. Từ mã hóa (PKE) đến đóng gói khóa (KEM)

Lược đồ ở mục 5 mới chỉ an toàn trước kẻ tấn công **nghe lén thụ động (IND-CPA)**. Kẻ tấn công **chủ động** có thể gửi bản mã giả mạo rồi quan sát Alice giải mã thành công hay thất bại để dò khóa bí mật (**reaction attack**).

HQC khắc phục bằng **biến đổi Fujisaki-Okamoto (FO)**:

```
Encaps (Bob):
  1. Chọn m ngẫu nhiên, salt ngẫu nhiên
  2. Sinh r₁, r₂, e một cách TẤT ĐỊNH từ hash(m, pk, salt)
  3. c = Encrypt(pk, m)
  4. Khóa chung K = hash(m, c)

Decaps (Alice):
  1. m' = Decrypt(sk, c)
  2. Mã hóa lại: c' = Encrypt(pk, m') với cùng cách sinh nhiễu
  3. Nếu c' == c  → K = hash(m', c)
     Ngược lại   → K = hash(σ, c)    (σ bí mật: "từ chối ngầm", kẻ tấn công không biết là thất bại)
```

**Ý nghĩa**: Alice **kiểm tra lại** bản mã có được tạo đúng cách không. Bản mã giả mạo sẽ nhận về một khóa rác trông ngẫu nhiên → kẻ tấn công không học được gì. Kết quả: KEM đạt an toàn **IND-CCA2**.

**Vì sao cần DFR (tỷ lệ giải mã thất bại) cực nhỏ?** Nếu đôi khi `e'` quá nặng khiến giải mã thất bại, các lần thất bại đó có thể lộ thông tin về `(x, y)`. HQC chọn tham số để DFR < 2⁻¹²⁸ (HQC-128) – nghĩa là trong thực tế **không bao giờ** xảy ra.

---

## 9. Chạy thử HQC thật bằng Python (liboqs)

Thư viện **liboqs** của dự án Open Quantum Safe cung cấp cài đặt HQC.

### Cài đặt

```bash
# Cần liboqs (thư viện C) + gói Python liboqs-python
pip install liboqs-python
# Lần import đầu tiên, liboqs-python có thể tự tải và build liboqs (cần CMake + trình biên dịch C)
```

### Mã ví dụ

```python
import oqs

KEM_ALG = "HQC-128"

# Kiểm tra HQC có được bật trong bản liboqs đang dùng không
enabled = oqs.get_enabled_kem_mechanisms()
print([k for k in enabled if "HQC" in k])

with oqs.KeyEncapsulation(KEM_ALG) as alice:
    # Alice sinh cặp khóa
    public_key = alice.generate_keypair()

    with oqs.KeyEncapsulation(KEM_ALG) as bob:
        # Bob đóng gói: tạo bản mã và khóa chung
        ciphertext, shared_secret_bob = bob.encap_secret(public_key)

    # Alice mở gói: lấy lại khóa chung
    shared_secret_alice = alice.decap_secret(ciphertext)

print("Khóa công khai:", len(public_key), "byte")
print("Bản mã        :", len(ciphertext), "byte")
print("Khóa chung    :", len(shared_secret_alice), "byte")
print("Khớp nhau?    :", shared_secret_alice == shared_secret_bob)
```

> ⚠️ **Lưu ý**: Một số phiên bản liboqs **tắt HQC theo mặc định** (do phát hiện lỗi trong cài đặt và đang chờ cập nhật theo chuẩn NIST mới). Nếu danh sách in ra rỗng, cần build liboqs với tùy chọn bật HQC hoặc dùng phiên bản mới hơn. Chỉ dùng cho **học tập / thử nghiệm**, chưa dùng cho sản phẩm thực tế đến khi có chuẩn FIPS chính thức.

Ngoài ra có thể xem bản cài đặt đồ chơi thuần Python trong mục 12 của [HQC_Post_Quantum_Cryptography.md](HQC_Post_Quantum_Cryptography.md#12-ví-dụ-minh-họa-toy-example).

---

## 10. Những hiểu lầm thường gặp

| Hiểu lầm | Thực tế |
|---|---|
| "HQC là thuật toán lượng tử, cần máy tính lượng tử để chạy" | ❌ HQC chạy trên máy tính thường; nó **chống lại** máy tính lượng tử. |
| "HQC thay thế ML-KEM (Kyber)" | ❌ HQC là **phương án dự phòng**; ML-KEM vẫn là lựa chọn chính. |
| "Mã Reed-Muller/Reed-Solomon là bí mật" | ❌ Mã sửa lỗi **công khai**. Bí mật là các vector thưa `x, y`. |
| "HQC giống McEliece" | ⚠️ Cùng họ mã sửa lỗi, nhưng McEliece **giấu cấu trúc mã** trong khóa công khai; HQC dùng **mã ngẫu nhiên** cho an toàn và mã công khai riêng để sửa lỗi. |
| "HQC dùng để ký số" | ❌ HQC chỉ là **KEM** (thiết lập khóa). Ký số dùng ML-DSA, SLH-DSA, FN-DSA... |
| "Giải mã thất bại là lỗi của thuật toán" | ⚠️ Đó là **đặc tính có chủ đích**, xác suất được khống chế dưới 2⁻¹²⁸. |
| "Cài đúng công thức là đủ an toàn" | ❌ Phải cài đặt **thời gian hằng (constant-time)**; HQC từng bị tấn công timing thực tế. |

---

## 11. Câu hỏi ôn tập và bài tập

### Câu hỏi lý thuyết
1. Chữ "H" và "QC" trong HQC nghĩa là gì?
2. Vì sao khóa bí mật `x, y` phải là vector **thưa**? Điều gì xảy ra nếu chúng dày?
3. Trong phép giải mã, hạng tử nào bị triệt tiêu, và vì sao Alice làm được còn kẻ tấn công thì không?
4. Vì sao HQC cần biến đổi Fujisaki-Okamoto?
5. Nêu một ưu điểm và một nhược điểm của HQC so với ML-KEM.

### Bài tập tính toán
6. Với n = 5, tính `(1 + X²) · (X + X³)` trong `F₂[X]/(X⁵ − 1)`.
7. Làm lại ví dụ mục 6 với `m = 0`, giữ nguyên các vector còn lại. Viết ra `v` và `v + u·y`.
8. Trong ví dụ mục 6, nếu `w = w_r = w_e = 2`, trọng số lớn nhất có thể của `e'` là bao nhiêu? Mã lặp độ dài 11 còn luôn sửa được không?

### Bài tập lập trình
9. Viết hàm `mul(a, b, n)` nhân hai đa thức trong `F₂[X]/(Xⁿ − 1)`, biểu diễn vector bằng số nguyên Python (dùng dịch bit và XOR).
10. Mở rộng code đồ chơi: chạy 10 000 lần với các giá trị `w` khác nhau, vẽ đồ thị tỷ lệ giải mã thất bại theo `w`.

<details>
<summary><b>Đáp án gợi ý</b></summary>

1. **H** = Hamming (đo lỗi bằng trọng số Hamming); **QC** = Quasi-Cyclic (mã tựa vòng, giúp khóa nhỏ).
2. Để `e' = x·r₂ − r₁·y + e` thưa, nằm trong khả năng sửa lỗi. Nếu `x, y` dày, `e'` dày → Alice cũng không giải mã được.
3. Hạng `h·y·r₂`. Alice biết `y` nên nhân `u` với `y` để khử; kẻ tấn công không biết `y` (tìm `y` là bài toán QCSD).
4. Để chống tấn công bản mã chọn trước (chủ động), nâng từ IND-CPA lên IND-CCA2.
5. Ưu: dựa trên bài toán khác lưới, đa dạng hóa, DFR phân tích chặt. Nhược: bản mã lớn hơn ~4 lần, chậm hơn.
6. `(1 + X²)(X + X³) = X + X³ + X³ + X⁵ = X + X⁵ = X + 1` (vì `X⁵ = 1`, hai `X³` triệt tiêu). Kết quả: `1 + X`.
7. `v = s·r₂ + e = {1, 3, 5, 9, 10}`; `v + u·y = {1,3,5,9,10} ⊕ {1,3,5,6,8,10} = {6, 8, 9}` → 3 bit 1 / 8 bit 0 → m = 0 ✓.
8. `w(x·r₂) ≤ 4`, `w(r₁·y) ≤ 4`, `w(e) = 2` → `w(e') ≤ 10` > 5 → **không** luôn sửa được; giải mã có thể thất bại. Đây là lý do HQC thật cần n lớn và mã sửa lỗi mạnh.
9. Gợi ý:
   ```python
   def mul(a, b, n):
       mask = (1 << n) - 1
       res = 0
       for i in range(n):
           if (a >> i) & 1:
               res ^= ((b << i) | (b >> (n - i))) & mask   # xoay vòng b sang i vị trí
       return res
   ```
10. Tự thực hiện – quan sát DFR tăng rất nhanh khi `w` tăng.

</details>

---

## 12. Lộ trình học tiếp

```
Tuần 1  ── Nền tảng
           • Đại số trên F₂, đa thức, vành thương
           • Mã tuyến tính, ma trận sinh/kiểm tra, hội chứng
           • Tài liệu: MacWilliams & Sloane (chương 1), Huffman & Pless

Tuần 2  ── Mã sửa lỗi dùng trong HQC
           • Mã lặp, Reed-Muller (giải mã bằng biến đổi Hadamard)
           • Reed-Solomon (Berlekamp-Massey), mã ghép

Tuần 3  ── Mật mã dựa trên mã
           • McEliece, Niederreiter, bài toán Syndrome Decoding
           • Thuật toán ISD: Prange → Stern → BJMM

Tuần 4  ── HQC chi tiết
           • Đọc đặc tả chính thức tại pqc-hqc.org
           • Bài báo IEEE Trans. IT 2018 của Aguilar Melchor et al.
           • Biến đổi FO, khái niệm IND-CPA / IND-CCA2

Tuần 5  ── Cài đặt & an toàn thực tế
           • Đọc mã nguồn tham chiếu HQC / PQClean
           • Lập trình constant-time, tấn công timing (Guo et al. 2022)
           • Thử nghiệm liboqs, đo hiệu năng so với ML-KEM

Tuần 6+ ── Mở rộng
           • So sánh HQC – BIKE – Classic McEliece
           • Tích hợp hybrid vào TLS 1.3 / SSH
           • Theo dõi bản chuẩn FIPS cho HQC của NIST
```

### Nguồn học được khuyến nghị
- Trang chính thức HQC: https://pqc-hqc.org
- NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography
- Open Quantum Safe (liboqs): https://openquantumsafe.org
- PQClean: https://github.com/PQClean/PQClean
- Sách: D. J. Bernstein, J. Buchmann, E. Dahmen (eds.) — *Post-Quantum Cryptography*, Springer 2009 (chương về code-based cryptography của R. Overbeck & N. Sendrier).

---

*Ghi chú: Tài liệu phục vụ học tập. Tham số và trạng thái chuẩn hóa của HQC có thể thay đổi – đối chiếu với đặc tả và công bố mới nhất của NIST.*
