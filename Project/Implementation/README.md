# Cài đặt HQC bằng Python

Cài đặt đầy đủ **HQC-KEM (Hamming Quasi-Cyclic)** – thuật toán đóng gói khóa hậu lượng tử được NIST chọn năm 2025 – bằng **Python thuần**, không cần thư viện ngoài. Mục đích: **học tập và nghiên cứu**.

Lý thuyết: xem [../Learning/Tim_hieu_HQC.md](../Learning/Tim_hieu_HQC.md) và [../Learning/HQC_Post_Quantum_Cryptography.md](../Learning/HQC_Post_Quantum_Cryptography.md).

> ⚠️ **Không dùng cho sản phẩm thực tế.** Code không chạy thời gian hằng (dễ bị tấn công timing) và không tương thích từng bit với bộ test vector (KAT) chính thức. Khi cần dùng thật, hãy dùng thư viện đã kiểm định như liboqs / PQClean.

---

## Yêu cầu

- Python **3.10+** (đã kiểm thử với 3.12)
- Không cần cài thêm gói nào (chỉ dùng `hashlib`, `secrets`, `hmac`)

## Chạy thử

```bash
cd Project/Implementation

python demo.py              # HQC-128
python demo.py HQC-256      # một mức cụ thể
python demo.py all          # cả 3 mức

python -m unittest -v       # chạy toàn bộ kiểm thử
```

Kết quả mẫu:

```
=== HQC-128 (an toàn 128 bit) ===
  [Alice] KeyGen  :      0.2 ms | pk = 2249 B, sk = 2305 B
  [Bob]   Encaps  :      0.5 ms | ct = 4433 B
  [Alice] Decaps  :      3.1 ms
  Khóa chung Bob  : 2968fbb655d8a9a1...
  Khóa chung Alice: 2968fbb655d8a9a1...
  Khớp nhau       : ✓
  Trọng số e' = x*r2 + r1*y + e : 6004 / 17664 bit
```

## Sử dụng như thư viện

```python
from hqc import HQCKEM, HQC_128

kem = HQCKEM(HQC_128)

pk, sk = kem.keygen()                 # Alice
ct, ss_bob = kem.encaps(pk)           # Bob
ss_alice = kem.decaps(sk, ct)         # Alice

assert ss_alice == ss_bob             # khóa chung 32 byte
```

---

## Cấu trúc mã nguồn

```
Implementation/
├── hqc/
│   ├── params.py        Bộ tham số HQC-128 / 192 / 256 và kích thước
│   ├── gf2x.py          Số học trong vành F2[X]/(X^n - 1) (số nguyên Python = vector bit)
│   ├── gf256.py         Trường GF(2^8), đa thức 0x11D
│   ├── reed_solomon.py  Mã RS rút gọn: mã hóa hệ thống, giải mã Berlekamp-Massey + Chien + Forney
│   ├── reed_muller.py   Mã RM(1,7) nhân bản, giải mã bằng biến đổi Hadamard nhanh
│   ├── code.py          Mã ghép RS ∘ RM (mã công khai C)
│   ├── xof.py           Sinh ngẫu nhiên từ seed bằng SHAKE256, lấy mẫu vector trọng số cố định
│   ├── pke.py           HQC.PKE: KeyGen / Encrypt / Decrypt (IND-CPA)
│   └── kem.py           HQC.KEM: KeyGen / Encaps / Decaps với biến đổi Fujisaki-Okamoto (IND-CCA2)
├── tests/test_hqc.py    14 kiểm thử
└── demo.py              Demo Alice–Bob, đo thời gian, in trọng số lỗi
```

## Ánh xạ thuật toán ↔ mã nguồn

| Bước | Công thức | Vị trí |
|---|---|---|
| KeyGen | `h ←$ R`, `x, y` trọng số w, `s = x + h·y` | [pke.py](hqc/pke.py) `HQCPKE.keygen` |
| Encrypt | `u = r1 + h·r2`, `v = trunc(mG + s·r2 + e)` | [pke.py](hqc/pke.py) `HQCPKE.encrypt` |
| Decrypt | `m = C.decode(v − u·y)` | [pke.py](hqc/pke.py) `HQCPKE.decrypt` |
| Encaps | `θ = G(H(pk)‖m‖salt)`, `K = K(m‖c‖salt)` | [kem.py](hqc/kem.py) `HQCKEM.encaps` |
| Decaps | Giải mã → mã hóa lại → so sánh → từ chối ngầm | [kem.py](hqc/kem.py) `HQCKEM.decaps` |
| Mã hóa mG | RS rồi RM nhân bản | [code.py](hqc/code.py) |

**Tối ưu chính**: mọi phép nhân trong HQC đều có một thừa số thưa (`y`, `r2`), nên `gf2x.mul_sparse` chỉ cần w phép xoay vòng + XOR trên số nguyên lớn thay vì nhân đa thức đầy đủ.

## Tham số và kích thước

| Bộ tham số | n | n1 | n2 | w | wr = we | pk | sk | ct | ss |
|---|---|---|---|---|---|---|---|---|---|
| HQC-128 | 17 669 | 46 | 384 | 66 | 75 | 2 249 | 2 305 | 4 433 | 32 |
| HQC-192 | 35 851 | 56 | 640 | 100 | 114 | 4 522 | 4 586 | 8 978 | 32 |
| HQC-256 | 57 637 | 90 | 640 | 131 | 149 | 7 245 | 7 317 | 14 421 | 32 |

Kích thước pk / sk / ct khớp với đặc tả HQC (có kiểm thử trong `TestParams`).

## Kiểm thử

| Nhóm | Nội dung |
|---|---|
| `TestParams` | Kích thước khớp đặc tả; `n1 − k = 2δ`; 2 là phần tử nguyên thủy mod n |
| `TestGF2X`, `TestGF256` | Phép nhân vòng, nghịch đảo trong GF(256) |
| `TestReedMuller` | Sửa đúng tới `(64·mult − 1)/2` lỗi bit cho cả 256 ký hiệu |
| `TestReedSolomon` | Sửa đúng tới δ lỗi ký hiệu; phát hiện khi quá nhiều lỗi |
| `TestConcatenatedCode` | Giải mã đúng dưới 3000 lỗi bit |
| `TestKEM` | Khóa chung khớp ở cả 3 mức; tất định theo seed; từ chối ngầm khi bản mã bị sửa; sai khóa bí mật thì khóa chung khác |

Thử nghiệm thêm với HQC-128: 300/300 lần Encaps/Decaps thành công; sau giải mã RM thường 0 byte sai (thỉnh thoảng 1 byte), trong khi RS sửa được tới 15 byte → biên an toàn lớn, phù hợp với DFR < 2⁻¹²⁸.

## Khác biệt so với đặc tả chính thức

Cài đặt giữ đúng **cấu trúc toán học, bộ tham số và kích thước** của HQC, nhưng đơn giản hóa một số chi tiết:

| Điểm | Đặc tả chính thức | Cài đặt này |
|---|---|---|
| Sinh ngẫu nhiên | SHAKE256 với định dạng seed/domain riêng của HQC | SHAKE256 dạng bộ đếm, domain tự định nghĩa |
| Lấy mẫu vector trọng số cố định | Thuật toán constant-time riêng | Thuật toán Floyd + rejection sampling (không constant-time) |
| Hàm băm G, H, K | Định dạng đầu vào theo đặc tả | Tương tự về ý tưởng, khác chi tiết byte |
| Giải mã RS / RM | Constant-time | Thông thường (có rẽ nhánh phụ thuộc dữ liệu) |
| Test vector KAT | Có | **Không tương thích** |

→ Hai bên cùng dùng cài đặt này thì trao đổi khóa đúng, nhưng **không** trao đổi được với liboqs hay cài đặt tham chiếu của NIST.

## Hướng phát triển

- Viết lại phần lấy mẫu và giải mã theo kiểu constant-time.
- Làm khớp từng bit với đặc tả mới nhất và kiểm tra bằng bộ KAT chính thức.
- Đo tỷ lệ giải mã thất bại theo thực nghiệm với các tham số thu nhỏ.
- So sánh hiệu năng với liboqs (bản C tối ưu AVX2).
