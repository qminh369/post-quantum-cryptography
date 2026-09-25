# HQC trong Mật mã Hậu Lượng tử (HQC in Post-Quantum Cryptography)

> Tài liệu nghiên cứu về lược đồ đóng gói khóa **HQC (Hamming Quasi-Cyclic)** – thuật toán dựa trên mã sửa lỗi được NIST lựa chọn năm 2025 làm chuẩn KEM dự phòng cho ML-KEM (Kyber).

---

## Mục lục

1. [Bối cảnh: Vì sao cần mật mã hậu lượng tử](#1-bối-cảnh-vì-sao-cần-mật-mã-hậu-lượng-tử)
2. [Tổng quan về HQC](#2-tổng-quan-về-hqc)
3. [Nền tảng toán học](#3-nền-tảng-toán-học)
4. [Bài toán khó làm cơ sở an toàn](#4-bài-toán-khó-làm-cơ-sở-an-toàn)
5. [Mô tả lược đồ HQC](#5-mô-tả-lược-đồ-hqc)
6. [Mã sửa lỗi được sử dụng: Reed-Muller ghép Reed-Solomon](#6-mã-sửa-lỗi-được-sử-dụng-reed-muller-ghép-reed-solomon)
7. [Bộ tham số và kích thước](#7-bộ-tham-số-và-kích-thước)
8. [So sánh với các KEM hậu lượng tử khác](#8-so-sánh-với-các-kem-hậu-lượng-tử-khác)
9. [Phân tích an toàn và các tấn công](#9-phân-tích-an-toàn-và-các-tấn-công)
10. [Tấn công kênh kề và vấn đề cài đặt](#10-tấn-công-kênh-kề-và-vấn-đề-cài-đặt)
11. [Quá trình chuẩn hóa NIST](#11-quá-trình-chuẩn-hóa-nist)
12. [Ví dụ minh họa (toy example)](#12-ví-dụ-minh-họa-toy-example)
13. [Ưu điểm, hạn chế và hướng nghiên cứu](#13-ưu-điểm-hạn-chế-và-hướng-nghiên-cứu)
14. [Thuật ngữ](#14-thuật-ngữ)
15. [Tài liệu tham khảo](#15-tài-liệu-tham-khảo)

---

## 1. Bối cảnh: Vì sao cần mật mã hậu lượng tử

Các hệ mật khóa công khai phổ biến hiện nay (RSA, Diffie-Hellman, ECC) dựa trên bài toán **phân tích số nguyên** và **logarit rời rạc**. Thuật toán **Shor (1994)** cho phép máy tính lượng tử đủ lớn giải các bài toán này trong thời gian đa thức → toàn bộ hạ tầng khóa công khai hiện tại sẽ bị phá vỡ.

Mối đe dọa **"Harvest now, decrypt later"** (thu thập bây giờ, giải mã sau): kẻ tấn công có thể lưu trữ lưu lượng mã hóa hôm nay và giải mã khi có máy tính lượng tử. Vì vậy cơ chế **trao đổi/đóng gói khóa (KEM)** là thành phần cần chuyển đổi cấp bách nhất.

**Mật mã hậu lượng tử (PQC)** là các thuật toán chạy trên máy tính cổ điển nhưng được tin là an toàn trước cả máy tính lượng tử. Các họ chính:

| Họ | Bài toán khó | Ví dụ |
|---|---|---|
| Dựa trên lưới (Lattice) | LWE, Module-LWE, NTRU | ML-KEM (Kyber), ML-DSA (Dilithium), FN-DSA (Falcon) |
| **Dựa trên mã (Code-based)** | **Giải mã hội chứng (Syndrome Decoding)** | **HQC**, Classic McEliece, BIKE |
| Dựa trên hàm băm (Hash-based) | Tính chất hàm băm | SLH-DSA (SPHINCS+), XMSS, LMS |
| Đa biến (Multivariate) | Giải hệ phương trình đa thức | UOV, MAYO |
| Isogeny | Đồng cấu giữa đường cong elliptic | SQIsign (SIKE đã bị phá năm 2022) |

**Vì sao cần HQC khi đã có ML-KEM?** – Để **đa dạng hóa giả định toán học**. Nếu một đột phá toán học phá được bài toán lưới, thế giới cần một KEM dựa trên nền tảng hoàn toàn khác. Mật mã dựa trên mã có lịch sử từ năm 1978 (McEliece) và đã chịu được gần 50 năm phân tích mã.

---

## 2. Tổng quan về HQC

| Thuộc tính | Giá trị |
|---|---|
| Tên đầy đủ | Hamming Quasi-Cyclic |
| Loại | KEM (Key Encapsulation Mechanism), an toàn IND-CCA2 |
| Họ | Mật mã dựa trên mã sửa lỗi, metric Hamming |
| Bài toán nền | Quasi-Cyclic Syndrome Decoding (QCSD) – dạng quyết định |
| Công bố gốc | Aguilar Melchor, Aragon, Bettaieb, Bidoux, Blazy, Deneuville, Gaborit, Persichetti, Zémor, ... (2016; IEEE Trans. Inf. Theory 2018) |
| Tiền thân ý tưởng | Lược đồ của **Alekhnovich (2003)** – mã hóa dựa trên mã ngẫu nhiên |
| Trạng thái NIST | Được chọn chuẩn hóa ngày **11/03/2025** (kết thúc Vòng 4) |

**Ý tưởng cốt lõi**: Khác với McEliece (giấu một mã có cấu trúc – mã Goppa – bên trong khóa công khai), HQC **tách biệt** hai vai trò:

- Một mã **ngẫu nhiên quasi-cyclic** dùng để **bảo mật** (tạo khóa công khai, che giấu thông điệp).
- Một mã **công khai, có cấu trúc, giải mã hiệu quả** (Reed-Muller + Reed-Solomon) dùng để **sửa lỗi** – mã này không cần giữ bí mật.

Nhờ đó an toàn của HQC **không phụ thuộc vào việc che giấu cấu trúc mã** – điểm yếu lịch sử của nhiều biến thể McEliece (nhiều biến thể dùng mã Reed-Solomon, mã QC-MDPC có cấu trúc đã bị phá bằng tấn công cấu trúc). HQC quy an toàn về bài toán giải mã mã ngẫu nhiên (quasi-cyclic).

Giá phải trả: HQC có **xác suất giải mã thất bại (DFR – Decryption Failure Rate)** khác 0, nhưng DFR này **phân tích được chính xác** nhờ dùng mã công khai với đặc tính đã biết.

---

## 3. Nền tảng toán học

### 3.1. Mã tuyến tính và metric Hamming

- Mã tuyến tính `C[n, k]` trên `F₂` là không gian con k chiều của `F₂ⁿ`.
- **Trọng số Hamming** `w(x)` = số bit 1 trong x. **Khoảng cách Hamming** `d(x, y) = w(x ⊕ y)`.
- **Ma trận sinh** `G ∈ F₂^{k×n}`: mã từ `c = mG`.
- **Ma trận kiểm tra chẵn lẻ** `H ∈ F₂^{(n−k)×n}`: `c ∈ C ⟺ Hcᵀ = 0`.
- **Hội chứng (syndrome)** của vector y: `s = Hyᵀ`.

### 3.2. Vành đa thức và mã vòng (cyclic)

HQC làm việc trong vành:

```
R = F₂[X] / (Xⁿ − 1)
```

Mỗi vector `v = (v₀, ..., v_{n−1}) ∈ F₂ⁿ` được đồng nhất với đa thức `v(X) = Σ vᵢ Xⁱ`. Phép nhân hai phần tử trong R tương ứng với **tích chập vòng**, và có thể viết dưới dạng nhân với **ma trận xoay vòng (circulant)**:

```
        ⎡ h₀     h₁   ...  h_{n−1} ⎤
rot(h)= ⎢ h_{n−1} h₀  ...  h_{n−2} ⎥
        ⎢  ...                     ⎥
        ⎣ h₁     h₂   ...  h₀      ⎦
```

`u · v = u · rot(v)` (nhân vector-ma trận).

**Yêu cầu chọn n**: n là **số nguyên tố** sao cho **2 là phần tử nguyên thủy modulo n**. Khi đó `Xⁿ − 1 = (X − 1)·Φₙ(X)` với `Φₙ` bất khả quy trên F₂ → tránh được các tấn công khai thác phân tích nhân tử của `Xⁿ − 1` (như tấn công dạng "folding").

### 3.3. Mã quasi-cyclic (QC)

Mã `[sn, n]` được gọi là **quasi-cyclic bậc s** nếu dịch vòng đồng thời mỗi khối n bit của một mã từ cho ra mã từ khác. Ma trận kiểm tra có dạng khối circulant, ví dụ với s = 2:

```
H = [ Iₙ | rot(h) ]
```

Ưu điểm: khóa chỉ cần lưu **một hàng** (n bit) thay vì ma trận n×n → **giảm kích thước khóa từ O(n²) xuống O(n)**.

---

## 4. Bài toán khó làm cơ sở an toàn

### 4.1. Syndrome Decoding (SD)

> **Cho** ma trận ngẫu nhiên `H ∈ F₂^{(n−k)×n}`, hội chứng `s ∈ F₂^{n−k}` và trọng số `w`.
> **Tìm** `e ∈ F₂ⁿ` sao cho `Heᵀ = s` và `w(e) = w`.

Bài toán này được **Berlekamp, McEliece, van Tilborg (1978)** chứng minh là **NP-đầy đủ**. Chưa có thuật toán lượng tử nào cho tăng tốc vượt quá mức "căn bậc hai" kiểu Grover.

### 4.2. Quasi-Cyclic Syndrome Decoding (QCSD) – dạng dùng trong HQC

**2-QCSD (tìm kiếm)**: Cho `h ∈ R` ngẫu nhiên và `s = x + h·y` với `x, y ∈ R` có trọng số w. Tìm `(x, y)`.

**Decisional 2-QCSD (DQCSD)**: Phân biệt `(h, x + h·y)` với `(h, s)` trong đó s ngẫu nhiên đều.

Tương tự, **3-QCSD** dùng cho phần mã hóa: `(u, v) = (r₁ + h·r₂, s·r₂ + e)`.

**Lưu ý**: Dạng quasi-cyclic *chưa có* chứng minh NP-khó như SD tổng quát, nhưng không có tấn công nào khai thác cấu trúc QC hiệu quả hơn đáng kể ngoài tăng tốc cỡ `√n` (kỹ thuật **DOOM** – Decoding One Out of Many của Sendrier).

**Sự tương đồng với LWE**: HQC có cấu trúc gần như giống hệt Ring-LWE / lược đồ LPR:

| | Ring-LWE (LPR) | HQC |
|---|---|---|
| Khóa công khai | `(a, b = a·s + e)` | `(h, s = x + h·y)` |
| "Nhiễu" | nhỏ theo chuẩn Euclid | thưa theo trọng số Hamming |
| Khôi phục | làm tròn | giải mã bằng mã sửa lỗi |

Vì vậy HQC đôi khi được gọi là **"phiên bản mã sửa lỗi của Ring-LWE"**.

---

## 5. Mô tả lược đồ HQC

### 5.1. HQC.PKE – mã hóa khóa công khai (an toàn IND-CPA)

**Tham số**: `n` (độ dài vành), `n₁n₂` (độ dài mã công khai C, `n₁n₂ ≤ n`), `k` (độ dài thông điệp), trọng số `w, w_r, w_e`. Mã công khai C có ma trận sinh `G ∈ F₂^{k × n₁n₂}`.

**Setup(1^λ)** → tham số công khai.

**KeyGen:**
```
h  ←$ R                           (ngẫu nhiên đều, sinh từ seed)
x, y ←$ R, với w(x) = w(y) = w    (vector thưa)
s  = x + h·y
pk = (h, s)       sk = (x, y)
```

**Encrypt(pk, m)** với `m ∈ F₂ᵏ`:
```
e  ←$ R, w(e) = w_e
r₁, r₂ ←$ R, w(r₁) = w(r₂) = w_r
u = r₁ + h·r₂
v = truncate( m·G + s·r₂ + e , n₁n₂ bit )
c = (u, v)
```

**Decrypt(sk, c):**
```
return C.Decode( v − u·y )
```

### 5.2. Tính đúng đắn

```
v − u·y = mG + s·r₂ + e − (r₁ + h·r₂)·y
        = mG + (x + h·y)·r₂ + e − r₁·y − h·r₂·y
        = mG + x·r₂ − r₁·y + e
                 └─────── e' ───────┘
```

Vector lỗi `e' = x·r₂ − r₁·y + e` có trọng số tương đối nhỏ vì `x, y, r₁, r₂, e` đều thưa. Nếu `w(e')` nằm trong khả năng sửa lỗi của C thì giải mã thành công và thu được m.

- Trọng số trung bình của `x·r₂` xấp xỉ `w·w_r` (có thể nhỏ hơn do triệt tiêu).
- Phân tích phân phối của `e'` cho phép tính được **DFR** một cách chặt chẽ – đây là điểm mạnh then chốt của HQC so với BIKE.

### 5.3. HQC.KEM – đóng gói khóa (an toàn IND-CCA2)

HQC dùng **biến đổi Fujisaki-Okamoto (FO)** theo biến thể **HHK (Hofheinz-Hövelmanns-Kiltz 2017)** với **implicit rejection**, cùng với **salt** (được bổ sung trong các bản cập nhật để chống tấn công đa mục tiêu):

**Encaps(pk):**
```
m    ←$ F₂ᵏ
salt ←$ {0,1}^128
θ    = G(m ‖ pk ‖ salt)           // hàm băm → seed cho tính ngẫu nhiên
c    = HQC.PKE.Encrypt(pk, m; θ)  // mã hóa tất định
K    = K(m ‖ c)                   // khóa chung
return (c, salt), K
```

**Decaps(sk, (c, salt)):**
```
m'  = HQC.PKE.Decrypt(sk, c)
θ'  = G(m' ‖ pk ‖ salt)
c'  = HQC.PKE.Encrypt(pk, m'; θ')
if c' == c:  K = K(m' ‖ c)
else:        K = K(σ ‖ c)         // σ: giá trị bí mật ngẫu nhiên (implicit rejection)
```

Các hàm băm G, H, K được dựng từ **SHAKE256 / SHA-3** với tách miền (domain separation). Việc **mã hóa lại (re-encryption)** trong Decaps phải cài đặt **thời gian hằng (constant-time)**, nếu không sẽ lộ thông tin (xem mục 10).

### 5.4. Nén khóa bằng seed

- `h` được sinh từ một seed 40 byte → khóa công khai chỉ cần lưu `seed_h ‖ s`.
- Khóa bí mật có thể lưu dạng seed rồi tái tạo `(x, y)` khi cần.

---

## 6. Mã sửa lỗi được sử dụng: Reed-Muller ghép Reed-Solomon

HQC dùng **mã ghép (concatenated code)** `C = RS ∘ RM`:

```
     m (k bit)
        │
        ▼
 ┌──────────────────┐
 │ Mã ngoài:        │   Reed-Solomon rút gọn trên F₂₅₆
 │ RS [n₁, k₁]      │   (mỗi ký hiệu = 1 byte)
 └──────────────────┘
        │ n₁ ký hiệu
        ▼
 ┌──────────────────┐
 │ Mã trong:        │   Reed-Muller RM(1,7) [128, 8, 64]
 │ RM nhân bản      │   được lặp lại (duplicated) 3 hoặc 5 lần
 └──────────────────┘   → n₂ = 384 hoặc 640 bit
        │ n₁·n₂ bit
        ▼
     mG
```

- **Mã trong – Reed-Muller RM(1,7)**: mã hóa 1 byte thành 128 bit, khoảng cách tối thiểu 64. Được **nhân bản** (lặp) để tăng khả năng sửa lỗi. Giải mã bằng **biến đổi Hadamard nhanh (FHT)** – giải mã hợp lý cực đại (maximum likelihood), rất hiệu quả.
- **Mã ngoài – Reed-Solomon rút gọn**: sửa các ký hiệu (byte) mà mã trong giải sai. Giải mã bằng **Berlekamp-Massey** + tìm nghiệm + **Forney**.

**Lịch sử**: Phiên bản HQC ban đầu dùng **BCH ghép mã lặp (repetition)**. Từ Vòng 3 (2020) chuyển sang **RM-RS** giúp giảm kích thước khóa/bản mã khoảng 17% nhờ khả năng sửa lỗi tốt hơn với cùng độ dài.

Mã có **cấu trúc công khai** là hoàn toàn chấp nhận được, vì an toàn đến từ mã QC ngẫu nhiên chứ không từ việc giấu C.

---

## 7. Bộ tham số và kích thước

Tham số theo đặc tả HQC các vòng gần đây (Round 4). Tên mới trong quá trình chuẩn hóa: HQC-1 / HQC-3 / HQC-5 (tương ứng HQC-128 / HQC-192 / HQC-256).

| Bộ tham số | Mức NIST | n | n₁ | n₂ | w | w_r = w_e | DFR |
|---|---|---|---|---|---|---|---|
| HQC-128 | 1 (≈ AES-128) | 17 669 | 46 | 384 | 66 | 75 | < 2⁻¹²⁸ |
| HQC-192 | 3 (≈ AES-192) | 35 851 | 56 | 640 | 100 | 114 | < 2⁻¹⁹² |
| HQC-256 | 5 (≈ AES-256) | 57 637 | 90 | 640 | 131 | 149 | < 2⁻²⁵⁶ |

**Kích thước (byte)**:

| Bộ tham số | Khóa công khai | Bản mã |
|---|---|---|
| HQC-128 | 2 249 | 4 433 |
| HQC-192 | 4 522 | 8 978 |
| HQC-256 | 7 245 | 14 421 |

> ⚠️ Các con số có thể thay đổi nhẹ trong bản chuẩn FIPS cuối cùng (ví dụ kích thước khóa bí mật, độ dài khóa chung, định dạng salt). Luôn đối chiếu với tài liệu NIST mới nhất.

**Hiệu năng**: Nhờ phép nhân đa thức trên F₂ (có thể tăng tốc bằng lệnh `PCLMULQDQ`/AVX2, Karatsuba) và giải mã RM bằng FHT, HQC đạt tốc độ ở mức vài chục đến vài trăm nghìn chu kỳ CPU cho mỗi thao tác trên x86 tối ưu – chậm hơn ML-KEM nhưng hoàn toàn thực tế cho TLS/VPN.

---

## 8. So sánh với các KEM hậu lượng tử khác

Mức an toàn NIST 1, kích thước tính bằng byte (xấp xỉ):

| Thuật toán | Họ | Khóa công khai | Bản mã | Ghi chú |
|---|---|---|---|---|
| ML-KEM-512 | Lưới (MLWE) | 800 | 768 | Chuẩn chính FIPS 203 (2024) |
| **HQC-128** | **Mã QC, Hamming** | **2 249** | **4 433** | **Chuẩn dự phòng (chọn 2025)** |
| BIKE-L1 | Mã QC-MDPC | 1 541 | 1 573 | Không được chọn – DFR khó chứng minh |
| Classic McEliece 348864 | Mã Goppa | 261 120 | 96 | Không được NIST chọn ở Vòng 4; khóa rất lớn |

### HQC vs BIKE
- BIKE **nhỏ gọn hơn** (khóa và bản mã nhỏ hơn).
- BIKE dùng giải mã **bit-flipping** lặp cho mã QC-MDPC; DFR của nó chủ yếu **ước lượng bằng mô phỏng và mô hình ngoại suy**, khó chứng minh chặt đến mức 2⁻¹²⁸ – điều bắt buộc để đạt IND-CCA2.
- HQC có **phân tích DFR chặt chẽ, được tin cậy hơn**, thiết kế đơn giản hơn, sinh khóa nhanh.
- NIST (NIST IR 8545) đánh giá HQC có **độ tin cậy an toàn cao hơn** dù kích thước lớn hơn → chọn HQC.

### HQC vs Classic McEliece
- McEliece: bản mã **cực nhỏ**, lịch sử lâu nhất (1978), độ tin cậy rất cao, nhưng khóa công khai **hàng trăm KB đến hơn 1 MB** – không phù hợp cho giao thức cần gửi khóa thường xuyên như TLS.
- HQC: cân bằng hơn, khóa và bản mã đều vài KB.

### HQC vs ML-KEM
- ML-KEM nhỏ hơn và nhanh hơn → vẫn là **lựa chọn mặc định**.
- HQC đóng vai trò **"bảo hiểm"**: nếu lưới bị phá, HQC vẫn đứng vững vì dựa trên bài toán hoàn toàn khác.

---

## 9. Phân tích an toàn và các tấn công

### 9.1. Chứng minh an toàn
- **HQC.PKE** đạt **IND-CPA** dưới giả định **DQCSD 2-QCSD và 3-QCSD** (chứng minh trong mô hình chuẩn).
- **HQC.KEM** đạt **IND-CCA2** trong mô hình **ROM** (và QROM) qua biến đổi FO/HHK, **với điều kiện DFR đủ nhỏ** (DFR ≤ 2^{−λ}). Đây chính là lý do DFR quan trọng: tấn công dựa trên lỗi giải mã (reaction attacks – như tấn công của Guo, Johansson, Stankovski 2016 phá QC-MDPC) có thể khôi phục khóa bí mật nếu DFR lớn.

### 9.2. Tấn công cổ điển: Information Set Decoding (ISD)
Tấn công tổng quát tốt nhất lên bài toán SD là họ thuật toán **ISD**:

| Thuật toán | Năm |
|---|---|
| Prange | 1962 |
| Lee–Brickell, Leon, Stern | 1988–1989 |
| Dumer | 1991 |
| MMT (May–Meurer–Thomae) | 2011 |
| BJMM (Becker–Joux–May–Meurer) | 2012 |
| May–Ozerov, Both–May | 2015–2018 |

Với trọng số lỗi nhỏ tuyến tính theo `√n` (trường hợp của HQC), độ phức tạp ISD xấp xỉ `2^{−w·log₂(1−R)·(1+o(1))}` và các cải tiến tinh vi chỉ đem lại lợi ích nhỏ. Cấu trúc QC cho thêm tăng tốc `≈ √n` (DOOM) – đã được tính vào tham số.

### 9.3. Tấn công lượng tử
- **Grover** áp dụng vào ISD (Bernstein 2010) → giảm số mũ khoảng một nửa đối với phần tìm kiếm.
- Các biến thể ISD lượng tử dùng quantum walk (Kachigar–Tillich 2017) chỉ cải thiện nhỏ.
- **Không có** thuật toán kiểu Shor cho bài toán giải mã mã ngẫu nhiên.

### 9.4. Tấn công cấu trúc
- Tấn công dựa trên phân tích nhân tử `Xⁿ − 1` → đã chặn bằng cách chọn n nguyên tố với 2 nguyên thủy mod n.
- Tấn công dựa trên lỗi giải mã → chặn bằng DFR ≤ 2^{−λ} và FO transform.

---

## 10. Tấn công kênh kề và vấn đề cài đặt

HQC đã chịu nhiều nghiên cứu tấn công **kênh kề (side-channel)**, là bài học quan trọng khi triển khai:

| Tấn công | Mô tả | Biện pháp |
|---|---|---|
| **Timing trên giải mã BCH** (Wafo-Tapa et al., 2019–2020) | Thời gian giải mã BCH phụ thuộc số lỗi → rò rỉ khóa bí mật | Giải mã thời gian hằng; chuyển sang RM-RS |
| **Timing trên lấy mẫu vector trọng số cố định** (Guo, Hlauschek, Johansson, Lahr, Nilsson, Schröder – 2022) | Rejection sampling trong khâu mã hóa lại (Decaps) có thời gian phụ thuộc seed → khôi phục khóa | Thuật toán sinh vector trọng số cố định constant-time |
| **Power/EM trên giải mã RM** (Schamberger et al., Goy et al.) | Phân tích năng lượng trong FHT / so sánh bản mã | Masking, shuffling |
| **Tấn công lỗi (Fault injection)** | Bỏ qua bước so sánh c' == c | Kiểm tra dư thừa, cài đặt chống lỗi |
| **Plaintext-checking oracle** | Kẻ tấn công quan sát việc Decaps chấp nhận/từ chối | Implicit rejection + constant-time comparison |

**Nguyên tắc cài đặt an toàn:**
1. Mọi thao tác phụ thuộc bí mật phải **constant-time** (không rẽ nhánh, không truy cập bộ nhớ phụ thuộc bí mật).
2. So sánh `c' == c` phải là so sánh thời gian hằng.
3. Sinh vector thưa theo cách không lộ thời gian.
4. Dùng thư viện đã kiểm định: **PQClean**, **liboqs (Open Quantum Safe)**, cài đặt tham chiếu/tối ưu của nhóm HQC (pqc-hqc.org).

---

## 11. Quá trình chuẩn hóa NIST

| Mốc thời gian | Sự kiện |
|---|---|
| 12/2016 | NIST kêu gọi đề xuất PQC |
| 11/2017 | HQC nộp vào Vòng 1 (69 ứng viên hợp lệ) |
| 01/2019 | HQC vào Vòng 2 |
| 07/2020 | HQC là **ứng viên thay thế (alternate)** Vòng 3; chuyển sang mã RM-RS |
| 07/2022 | NIST chọn **CRYSTALS-Kyber**; HQC, BIKE, Classic McEliece, SIKE vào **Vòng 4** (SIKE bị phá ngay sau đó) |
| 08/2024 | Công bố **FIPS 203 (ML-KEM)**, FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) |
| **11/03/2025** | NIST công bố **chọn HQC** làm KEM thứ hai để chuẩn hóa (báo cáo **NIST IR 8545**) |
| ~2026 | Dự kiến công bố **bản dự thảo chuẩn** cho HQC để lấy ý kiến công chúng |
| ~2027 | Dự kiến **chuẩn chính thức** |

**Lý do NIST chọn HQC** (tóm tắt từ NIST IR 8545):
- Dựa trên **bài toán khác lưới** → đa dạng hóa.
- **Phân tích DFR vững chắc** (điểm hơn BIKE).
- Hiệu năng tổng thể **chấp nhận được**, kích thước khóa hợp lý (điểm hơn Classic McEliece).
- Thiết kế đã ổn định, được phân tích lâu dài, các vấn đề kênh kề đã có biện pháp khắc phục.

**Khuyến nghị sử dụng của NIST**: ML-KEM vẫn là KEM chính cho hầu hết ứng dụng; HQC là **phương án dự phòng** nếu phát hiện điểm yếu của ML-KEM. Có thể dùng **lai (hybrid)** ví dụ `X25519 + ML-KEM` hoặc kết hợp ML-KEM + HQC để phòng thủ nhiều tầng.

---

## 12. Ví dụ minh họa (toy example)

Đoạn mã Python dưới đây minh họa **cấu trúc** HQC.PKE với tham số rất nhỏ và **mã lặp** thay cho RM-RS. **Chỉ dùng cho học tập – hoàn toàn không an toàn.**

```python
import random

n = 67            # số nguyên tố, 2 là phần tử nguyên thủy mod 67
REP = 13          # mã lặp: mỗi bit thông điệp lặp 13 lần
k = n // REP      # 5 bit thông điệp
w, wr, we = 3, 3, 3

def rand_sparse(weight):
    v = [0] * n
    for i in random.sample(range(n), weight):
        v[i] = 1
    return v

def rand_dense():
    return [random.randint(0, 1) for _ in range(n)]

def add(a, b):
    return [x ^ y for x, y in zip(a, b)]

def mul(a, b):
    """Nhân trong F2[X]/(X^n - 1) - tích chập vòng."""
    res = [0] * n
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj:
                    res[(i + j) % n] ^= 1
    return res

def encode(m):                     # mã lặp: mG
    c = []
    for bit in m:
        c += [bit] * REP
    return c + [0] * (n - len(c))

def decode(c):                     # giải mã theo đa số
    return [int(sum(c[i*REP:(i+1)*REP]) > REP // 2) for i in range(k)]

# --- KeyGen ---
h = rand_dense()
x, y = rand_sparse(w), rand_sparse(w)
s = add(x, mul(h, y))
pk, sk = (h, s), (x, y)

# --- Encrypt ---
m = [random.randint(0, 1) for _ in range(k)]
r1, r2, e = rand_sparse(wr), rand_sparse(wr), rand_sparse(we)
u = add(r1, mul(h, r2))
v = add(add(encode(m), mul(s, r2)), e)

# --- Decrypt ---
noisy = add(v, mul(u, y))          # = mG + x*r2 + r1*y + e   (trên F2: trừ = cộng)
m_dec = decode(noisy)

err = add(noisy, encode(m))
print("m       =", m)
print("m_dec   =", m_dec)
print("w(e')   =", sum(err))
print("Thành công:", m == m_dec)
```

**Quan sát**: trọng số `w(e') ≤ w·w_r + w_r·w + w_e = 21`, lỗi phân tán ngẫu nhiên trên 67 vị trí, nên mã lặp đa số thường giải mã đúng. Trong HQC thật, mã RM-RS có khả năng sửa lỗi mạnh hơn nhiều, cho phép DFR xuống dưới 2⁻¹²⁸.

---

## 13. Ưu điểm, hạn chế và hướng nghiên cứu

### Ưu điểm
- ✅ Dựa trên bài toán **giải mã mã ngẫu nhiên** – được nghiên cứu gần 50 năm, **độc lập với lưới**.
- ✅ **Không phải che giấu cấu trúc mã** → tránh cả một lớp tấn công cấu trúc.
- ✅ **DFR phân tích chặt chẽ** → đạt IND-CCA2 một cách đáng tin cậy.
- ✅ Kích thước khóa hợp lý hơn nhiều so với Classic McEliece.
- ✅ Tính toán chủ yếu là XOR, dịch bit, nhân đa thức nhị phân → phù hợp phần cứng (FPGA/ASIC).

### Hạn chế
- ❌ **Bản mã lớn** (~4.4 KB ở mức 1, ~14 KB ở mức 5) – lớn gấp ~5–13 lần ML-KEM; có thể gây phân mảnh gói tin trong TLS/QUIC/IKEv2.
- ❌ Chậm hơn ML-KEM.
- ❌ Nhạy cảm với **tấn công kênh kề** nếu cài đặt không cẩn thận (lịch sử đã có nhiều tấn công thực tế).
- ❌ Giả định QCSD chưa có quy dẫn về trường hợp xấu nhất (worst-case) như một số bài toán lưới.

### Hướng nghiên cứu mở
- Cài đặt **constant-time và masking** hiệu quả trên vi điều khiển (ARM Cortex-M4) và phần cứng.
- **Tích hợp giao thức**: TLS 1.3 hybrid, IKEv2, Signal/PQXDH, WireGuard hậu lượng tử.
- **Phân tích mật mã**: cải tiến ISD khai thác cấu trúc QC, ISD lượng tử.
- Các biến thể: **RQC** (rank metric – khóa nhỏ hơn), **HQC-RMRS** tối ưu, mã polar/LDPC thay mã ghép.
- **Kiểm chứng hình thức (formal verification)** cài đặt HQC (ví dụ bằng Jasmin/EasyCrypt như đã làm cho ML-KEM).
- Chiến lược **crypto-agility**: thiết kế hệ thống để có thể chuyển ML-KEM ↔ HQC khi cần.

---

## 14. Thuật ngữ

| Tiếng Anh | Tiếng Việt | Giải thích |
|---|---|---|
| Post-Quantum Cryptography (PQC) | Mật mã hậu lượng tử | Mật mã chống được máy tính lượng tử |
| KEM (Key Encapsulation Mechanism) | Cơ chế đóng gói khóa | Thiết lập khóa bí mật chung qua khóa công khai |
| Code-based cryptography | Mật mã dựa trên mã | Dựa trên độ khó giải mã mã tuyến tính ngẫu nhiên |
| Syndrome Decoding | Giải mã hội chứng | Tìm vector lỗi trọng số nhỏ từ hội chứng |
| Quasi-cyclic code | Mã tựa vòng | Mã có ma trận khối circulant |
| Hamming weight | Trọng số Hamming | Số phần tử khác 0 |
| DFR (Decryption Failure Rate) | Tỷ lệ giải mã thất bại | Xác suất bên nhận không khôi phục được thông điệp |
| ISD (Information Set Decoding) | Giải mã tập thông tin | Họ thuật toán tấn công tốt nhất lên SD |
| Concatenated code | Mã ghép | Mã ngoài kết hợp mã trong |
| Fujisaki-Okamoto transform | Biến đổi FO | Nâng IND-CPA lên IND-CCA2 |
| Implicit rejection | Từ chối ngầm | Trả khóa giả ngẫu nhiên thay vì báo lỗi |
| Side-channel attack | Tấn công kênh kề | Khai thác thời gian, năng lượng, bức xạ |
| Constant-time | Thời gian hằng | Thời gian thực thi không phụ thuộc dữ liệu bí mật |

---

## 15. Tài liệu tham khảo

1. C. Aguilar Melchor, N. Aragon, S. Bettaieb, L. Bidoux, O. Blazy, J.-C. Deneuville, P. Gaborit, G. Zémor, et al. — *Hamming Quasi-Cyclic (HQC)*, đặc tả nộp NIST (các phiên bản Round 1–4). Trang chính thức: https://pqc-hqc.org
2. C. Aguilar Melchor, O. Blazy, J.-C. Deneuville, P. Gaborit, G. Zémor — *Efficient Encryption From Random Quasi-Cyclic Codes*, IEEE Transactions on Information Theory, 64(5), 2018.
3. M. Alekhnovich — *More on Average Case vs Approximation Complexity*, FOCS 2003.
4. NIST — *NIST IR 8545: Status Report on the Fourth Round of the NIST Post-Quantum Cryptography Standardization Process*, 03/2025.
5. NIST — *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 08/2024.
6. E. Berlekamp, R. McEliece, H. van Tilborg — *On the inherent intractability of certain coding problems*, IEEE Trans. IT, 1978.
7. R. J. McEliece — *A Public-Key Cryptosystem Based on Algebraic Coding Theory*, DSN Progress Report, 1978.
8. D. Hofheinz, K. Hövelmanns, E. Kiltz — *A Modular Analysis of the Fujisaki-Okamoto Transformation*, TCC 2017.
9. N. Sendrier — *Decoding One Out of Many*, PQCrypto 2011.
10. A. Becker, A. Joux, A. May, A. Meurer — *Decoding Random Binary Linear Codes in 2^{n/20}*, EUROCRYPT 2012.
11. Q. Guo, C. Hlauschek, T. Johansson, N. Lahr, A. Nilsson, R. L. Schröder — *Don't Reject This: Key-Recovery Timing Attacks Due to Rejection-Sampling in HQC and BIKE*, TCHES 2022.
12. G. Wafo-Tapa, S. Bettaieb, L. Bidoux, P. Gaborit, E. Marcatel — *A Practicable Timing Attack Against HQC and its Countermeasure*, Advances in Mathematics of Communications, 2020.
13. D. J. Bernstein — *Grover vs. McEliece*, PQCrypto 2010.
14. Open Quantum Safe — liboqs: https://openquantumsafe.org
15. PQClean: https://github.com/PQClean/PQClean

---

*Ghi chú: Tài liệu tổng hợp cho mục đích học tập. Các tham số và trạng thái chuẩn hóa nên được đối chiếu lại với công bố mới nhất của NIST (csrc.nist.gov/projects/post-quantum-cryptography) vì chuẩn HQC đang trong quá trình hoàn thiện.*
