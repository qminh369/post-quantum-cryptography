# Mật mã Hậu Lượng tử (PQC) là gì? Có những loại nào?

> Tài liệu tổng quan về **Post-Quantum Cryptography (PQC)**: khái niệm, lý do cần thiết, các họ thuật toán chính, các chuẩn NIST và lộ trình chuyển đổi.
> Xem thêm tài liệu chuyên sâu: [HQC trong Mật mã Hậu Lượng tử](HQC_Post_Quantum_Cryptography.md).

---

## Mục lục

1. [PQC là gì?](#1-pqc-là-gì)
2. [Vì sao máy tính lượng tử đe dọa mật mã hiện nay?](#2-vì-sao-máy-tính-lượng-tử-đe-dọa-mật-mã-hiện-nay)
3. [Phân biệt PQC và Mật mã lượng tử (QKD)](#3-phân-biệt-pqc-và-mật-mã-lượng-tử-qkd)
4. [Hai loại chức năng: KEM và Chữ ký số](#4-hai-loại-chức-năng-kem-và-chữ-ký-số)
5. [Các họ thuật toán PQC](#5-các-họ-thuật-toán-pqc)
   - [5.1. Dựa trên lưới (Lattice-based)](#51-dựa-trên-lưới-lattice-based)
   - [5.2. Dựa trên mã sửa lỗi (Code-based)](#52-dựa-trên-mã-sửa-lỗi-code-based)
   - [5.3. Dựa trên hàm băm (Hash-based)](#53-dựa-trên-hàm-băm-hash-based)
   - [5.4. Đa biến (Multivariate)](#54-đa-biến-multivariate)
   - [5.5. Dựa trên isogeny](#55-dựa-trên-isogeny)
   - [5.6. Chữ ký từ MPC-in-the-Head / zero-knowledge](#56-chữ-ký-từ-mpc-in-the-head--zero-knowledge)
6. [Bảng so sánh tổng hợp](#6-bảng-so-sánh-tổng-hợp)
7. [Quá trình chuẩn hóa NIST](#7-quá-trình-chuẩn-hóa-nist)
8. [Lộ trình chuyển đổi và mô hình lai (hybrid)](#8-lộ-trình-chuyển-đổi-và-mô-hình-lai-hybrid)
9. [Ứng dụng thực tế hiện nay](#9-ứng-dụng-thực-tế-hiện-nay)
10. [Thách thức khi triển khai](#10-thách-thức-khi-triển-khai)
11. [Tài liệu tham khảo](#11-tài-liệu-tham-khảo)

---

## 1. PQC là gì?

**Mật mã hậu lượng tử (Post-Quantum Cryptography – PQC)**, còn gọi là *mật mã kháng lượng tử (quantum-resistant / quantum-safe cryptography)*, là tập hợp các thuật toán mật mã **khóa công khai**:

- **Chạy trên máy tính cổ điển** hiện nay (CPU, vi điều khiển, thẻ thông minh...), không cần phần cứng lượng tử.
- **Được tin là an toàn** trước kẻ tấn công sở hữu **cả máy tính cổ điển lẫn máy tính lượng tử** quy mô lớn.
- Có thể **thay thế trực tiếp** RSA, Diffie-Hellman, ECDH, ECDSA, EdDSA trong các giao thức hiện có (TLS, SSH, VPN, PKI, chữ ký mã nguồn...).

Điểm mấu chốt: PQC dựa trên **các bài toán toán học khác** (lưới, mã sửa lỗi, hàm băm, hệ đa thức...) mà hiện **chưa có thuật toán lượng tử nào giải hiệu quả**.

---

## 2. Vì sao máy tính lượng tử đe dọa mật mã hiện nay?

### 2.1. Thuật toán Shor (1994)
Giải bài toán **phân tích số nguyên** và **logarit rời rạc** (kể cả trên đường cong elliptic) trong **thời gian đa thức**.

→ Phá vỡ hoàn toàn: **RSA, DSA, Diffie-Hellman, ECDH, ECDSA, EdDSA**.

### 2.2. Thuật toán Grover (1996)
Tăng tốc tìm kiếm vét cạn theo **căn bậc hai**: tìm khóa n bit mất khoảng `2^(n/2)` phép thử thay vì `2^n`.

→ Chỉ **làm yếu** mật mã đối xứng và hàm băm, khắc phục bằng cách **tăng gấp đôi độ dài khóa** (dùng AES-256, SHA-384/512).

| Thuật toán hiện tại | Loại | Ảnh hưởng của máy tính lượng tử | Hành động |
|---|---|---|
| RSA, DH, ECC | Khóa công khai | **Bị phá hoàn toàn** (Shor) | **Thay bằng PQC** |
| AES-128 | Đối xứng | Còn ~64 bit an toàn (Grover) | Chuyển sang AES-256 |
| AES-256 | Đối xứng | Còn ~128 bit – vẫn an toàn | Giữ nguyên |
| SHA-256 | Hàm băm | Chống va chạm vẫn đủ an toàn | Giữ nguyên / dùng SHA-384 |

### 2.3. Vì sao phải chuyển đổi ngay từ bây giờ?

- **"Harvest Now, Decrypt Later" (HNDL)**: kẻ tấn công thu thập dữ liệu mã hóa hôm nay, chờ máy tính lượng tử để giải mã sau → dữ liệu cần giữ bí mật lâu dài (y tế, quốc phòng, tài chính, bí mật kinh doanh) **đã đang bị đe dọa**.
- **Định lý Mosca**: nếu `X + Y > Z` thì đã quá muộn, với:
  - `X` = thời gian dữ liệu cần được giữ bí mật,
  - `Y` = thời gian để chuyển đổi hệ thống sang PQC,
  - `Z` = thời gian đến khi có máy tính lượng tử đủ mạnh (CRQC – *Cryptographically Relevant Quantum Computer*).
- Chuyển đổi hạ tầng mật mã toàn cầu thường mất **10–20 năm**.

---

## 3. Phân biệt PQC và Mật mã lượng tử (QKD)

Hai khái niệm thường bị nhầm lẫn:

| Tiêu chí | **PQC** (Mật mã hậu lượng tử) | **QKD** (Phân phối khóa lượng tử) |
|---|---|---|
| Bản chất | Thuật toán toán học | Hiện tượng vật lý lượng tử (photon) |
| Phần cứng | Máy tính thông thường | Thiết bị quang học chuyên dụng, cáp quang/vệ tinh |
| Cơ sở an toàn | Độ khó bài toán toán học | Định luật vật lý (không thể sao chép trạng thái lượng tử) |
| Khoảng cách | Không giới hạn (qua Internet) | Giới hạn (~100 km cáp quang, cần trạm trung chuyển tin cậy) |
| Chức năng | Trao đổi khóa **và** chữ ký số | Chỉ trao đổi khóa, vẫn cần cơ chế xác thực |
| Chi phí, triển khai | Rẻ, cập nhật phần mềm | Đắt, hạ tầng riêng |
| Khuyến nghị (NSA, ANSSI, BSI, NCSC) | **Giải pháp chính** | Ứng dụng hạn chế, chuyên biệt |

---

## 4. Hai loại chức năng: KEM và Chữ ký số

PQC cần thay thế hai chức năng chính của mật mã khóa công khai:

### 4.1. KEM – Key Encapsulation Mechanism (Cơ chế đóng gói khóa)
Dùng để **thiết lập khóa bí mật chung** giữa hai bên (thay cho ECDH/RSA key transport).

```
Bên nhận:  (pk, sk) ← KeyGen()
Bên gửi:   (ct, K)  ← Encaps(pk)     → gửi ct
Bên nhận:  K        ← Decaps(sk, ct)
→ Cả hai có chung khóa K, dùng cho AES-GCM / ChaCha20-Poly1305
```

Mức độ khẩn cấp: **cao nhất** (vì mối đe dọa HNDL).

### 4.2. Chữ ký số (Digital Signature)
Dùng để **xác thực** và đảm bảo **toàn vẹn** (thay cho RSA-PSS, ECDSA, EdDSA): chứng chỉ số, cập nhật firmware, ký mã nguồn, tài liệu pháp lý.

Mức độ khẩn cấp: thấp hơn KEM về mặt dữ liệu (chữ ký chỉ cần an toàn tại thời điểm xác minh), nhưng **rất cấp bách với hệ thống có vòng đời dài** (root CA, firmware thiết bị IoT, ô tô, vệ tinh).

---

## 5. Các họ thuật toán PQC

### 5.1. Dựa trên lưới (Lattice-based)

**Bài toán khó**:
- **SVP / CVP** – tìm vector ngắn nhất / gần nhất trong lưới nhiều chiều.
- **LWE (Learning With Errors)** – giải hệ phương trình tuyến tính có nhiễu nhỏ: cho `(A, b = A·s + e)`, tìm `s`.
- Các biến thể có cấu trúc: **Ring-LWE, Module-LWE, NTRU, SIS**.

**Thuật toán tiêu biểu**:
| Thuật toán | Chức năng | Trạng thái |
|---|---|---|
| **ML-KEM** (CRYSTALS-Kyber) | KEM | **FIPS 203** (08/2024) |
| **ML-DSA** (CRYSTALS-Dilithium) | Chữ ký | **FIPS 204** (08/2024) |
| **FN-DSA** (Falcon) | Chữ ký | Chuẩn **FIPS 206** đang được NIST hoàn thiện |
| FrodoKEM | KEM | Không được NIST chọn; được BSI (Đức), ANSSI khuyến nghị cho mức bảo thủ |
| NTRU, NTRU Prime | KEM | NTRU Prime (sntrup761) dùng trong OpenSSH |
| HAWK | Chữ ký | Ứng viên vòng bổ sung chữ ký của NIST |

**Ưu điểm**: nhanh nhất, kích thước khóa/bản mã vừa phải (~1 KB), linh hoạt, có quy dẫn an toàn về trường hợp xấu nhất.
**Nhược điểm**: toán học còn tương đối mới so với mã sửa lỗi; Falcon khó cài đặt an toàn (dùng số thực dấu phẩy động, lấy mẫu Gauss).

---

### 5.2. Dựa trên mã sửa lỗi (Code-based)

**Bài toán khó**: **Syndrome Decoding** – giải mã một mã tuyến tính ngẫu nhiên (NP-đầy đủ, Berlekamp–McEliece–van Tilborg 1978).

**Thuật toán tiêu biểu**:
| Thuật toán | Chức năng | Trạng thái |
|---|---|---|
| **HQC** | KEM | **Được NIST chọn (03/2025)** làm KEM dự phòng cho ML-KEM |
| Classic McEliece | KEM | Không được NIST chọn; đang được chuẩn hóa tại ISO; khóa rất lớn (~261 KB – 1.3 MB) |
| BIKE | KEM | Dừng ở Vòng 4 NIST |
| CROSS, LESS | Chữ ký | Ứng viên vòng bổ sung chữ ký của NIST |

**Ưu điểm**: lịch sử lâu nhất (McEliece 1978), độ tin cậy cao, đa dạng hóa khỏi lưới.
**Nhược điểm**: khóa công khai hoặc bản mã lớn hơn lưới.

→ Chi tiết: [HQC_Post_Quantum_Cryptography.md](HQC_Post_Quantum_Cryptography.md)

---

### 5.3. Dựa trên hàm băm (Hash-based)

**Bài toán khó**: chỉ dựa vào tính chất của **hàm băm** (kháng tiền ảnh, kháng va chạm) → giả định an toàn **tối thiểu và bảo thủ nhất**.

**Nguyên lý**: chữ ký một lần (Lamport, Winternitz/WOTS+) kết hợp **cây Merkle** để ký nhiều thông điệp.

**Thuật toán tiêu biểu**:
| Thuật toán | Loại | Trạng thái |
|---|---|---|
| **SLH-DSA** (SPHINCS+) | Không trạng thái (stateless) | **FIPS 205** (08/2024) |
| **XMSS, LMS** | Có trạng thái (stateful) | NIST **SP 800-208**, RFC 8391, RFC 8554 |

**Ưu điểm**: an toàn được hiểu rõ nhất; phù hợp ký firmware, root CA.
**Nhược điểm**: chỉ làm được **chữ ký** (không có KEM); SLH-DSA có chữ ký lớn (~8–50 KB) và ký chậm; XMSS/LMS phải **quản lý trạng thái** cẩn thận (dùng lại trạng thái = mất an toàn).

---

### 5.4. Đa biến (Multivariate)

**Bài toán khó**: **MQ problem** – giải hệ phương trình đa thức bậc 2 nhiều biến trên trường hữu hạn (NP-khó).

**Thuật toán tiêu biểu**:
| Thuật toán | Trạng thái |
|---|---|
| Rainbow | **Bị phá** năm 2022 (Beullens – khôi phục khóa trong ~1 cuối tuần trên laptop) |
| **UOV** (Unbalanced Oil and Vinegar) | Ứng viên vòng bổ sung chữ ký NIST |
| **MAYO**, **SNOVA**, **QR-UOV** | Ứng viên vòng bổ sung chữ ký NIST |

**Ưu điểm**: **chữ ký rất nhỏ** (vài chục đến vài trăm byte), xác minh rất nhanh.
**Nhược điểm**: khóa công khai lớn (UOV hàng chục KB); lịch sử có nhiều lược đồ bị phá; chủ yếu chỉ làm chữ ký.

---

### 5.5. Dựa trên isogeny

**Bài toán khó**: tìm **đồng cấu (isogeny)** giữa hai **đường cong elliptic siêu kỳ dị (supersingular)**.

**Thuật toán tiêu biểu**:
| Thuật toán | Chức năng | Trạng thái |
|---|---|---|
| SIKE / SIDH | KEM | **Bị phá hoàn toàn** năm 2022 (Castryck–Decru, chỉ ~1 giờ trên một CPU) |
| CSIDH | Trao đổi khóa | Còn nghiên cứu, chậm, tranh luận về mức an toàn lượng tử |
| **SQIsign** | Chữ ký | Ứng viên vòng bổ sung chữ ký NIST |

**Ưu điểm**: **khóa và chữ ký nhỏ nhất** trong các họ PQC.
**Nhược điểm**: rất chậm, toán học phức tạp; sự sụp đổ của SIKE cho thấy họ này còn non trẻ.

**Bài học từ SIKE và Rainbow**: một thuật toán có thể trụ qua nhiều năm phân tích rồi bị phá đột ngột → cần **đa dạng hóa** và **mô hình lai**.

---

### 5.6. Chữ ký từ MPC-in-the-Head / zero-knowledge

Họ mới nổi: xây dựng chữ ký từ **chứng minh không tiết lộ (zero-knowledge proof)** cho một bài toán khó bất kỳ, dùng kỹ thuật **MPC-in-the-Head** hoặc **VOLE-in-the-Head**, biến đổi thành chữ ký qua **Fiat-Shamir**.

**Ví dụ** (ứng viên vòng bổ sung chữ ký NIST): **SDitH** (dựa trên mã), **Mirath**, **MQOM**, **PERK**, **RYDE**, **FAEST** (dựa trên AES).

**Ưu điểm**: khóa rất nhỏ, dựa trên giả định an toàn tối giản (ví dụ FAEST chỉ dựa trên AES).
**Nhược điểm**: chữ ký lớn (vài KB), ký/xác minh chậm hơn.

---

## 6. Bảng so sánh tổng hợp

### 6.1. So sánh theo họ

| Họ | Bài toán khó | KEM | Chữ ký | Tốc độ | Kích thước | Độ trưởng thành |
|---|---|---|---|---|---|---|
| Lưới | LWE, NTRU, SIS | ✅ | ✅ | Rất nhanh | Nhỏ–vừa | Cao |
| Mã sửa lỗi | Syndrome Decoding | ✅ | ✅ (mới) | Nhanh | Vừa–rất lớn | Rất cao |
| Hàm băm | Tính chất hàm băm | ❌ | ✅ | Ký chậm | Chữ ký lớn | Rất cao |
| Đa biến | MQ | ❌ | ✅ | Nhanh | Chữ ký nhỏ, khóa lớn | Trung bình |
| Isogeny | Isogeny siêu kỳ dị | ⚠️ | ✅ | Chậm | Rất nhỏ | Thấp |
| MPCitH / VOLEitH | Tùy chọn | ❌ | ✅ | Chậm | Khóa nhỏ, chữ ký vừa | Thấp |

### 6.2. Kích thước các thuật toán đã/đang chuẩn hóa (mức an toàn NIST 1–3, byte, xấp xỉ)

| Thuật toán | Khóa công khai | Bản mã / Chữ ký |
|---|---|---|
| ECDH X25519 (tham chiếu) | 32 | 32 |
| **ML-KEM-768** | 1 184 | 1 088 |
| **HQC-128** | 2 249 | 4 433 |
| Classic McEliece 348864 | 261 120 | 96 |
| Ed25519 (tham chiếu) | 32 | 64 |
| **ML-DSA-65** | 1 952 | 3 309 |
| **FN-DSA-512** (Falcon) | 897 | ~666 |
| **SLH-DSA-128s** | 32 | 7 856 |
| **SLH-DSA-128f** | 32 | 17 088 |

→ PQC nhìn chung có **khóa/bản mã/chữ ký lớn hơn nhiều lần** so với ECC – đây là thách thức lớn cho giao thức và thiết bị nhúng.

---

## 7. Quá trình chuẩn hóa NIST

| Thời gian | Sự kiện |
|---|---|
| 12/2016 | NIST kêu gọi đề xuất thuật toán PQC |
| 11/2017 | Nhận 82 đề xuất (69 hợp lệ ở Vòng 1) |
| 01/2019 | Vòng 2: 26 ứng viên |
| 07/2020 | Vòng 3: 7 ứng viên chính + 8 ứng viên thay thế |
| 07/2022 | Chọn **Kyber, Dilithium, Falcon, SPHINCS+**; mở Vòng 4 cho KEM (BIKE, Classic McEliece, HQC, SIKE) |
| 07/2022 | SIKE bị phá |
| 06/2023 | Vòng bổ sung chữ ký (on-ramp): 40 đề xuất |
| **08/2024** | Công bố **FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)** |
| 10/2024 | Vòng 2 bổ sung chữ ký: 14 ứng viên (CROSS, FAEST, HAWK, LESS, MAYO, Mirath, MQOM, PERK, QR-UOV, RYDE, SDitH, SNOVA, SQIsign, UOV) |
| 11/2024 | Dự thảo **NIST IR 8547** – lộ trình loại bỏ RSA/ECC |
| **03/2025** | Chọn **HQC** làm KEM thứ hai (NIST IR 8545) |
| 2025–2027 | Hoàn thiện FN-DSA (FIPS 206), chuẩn HQC, tiếp tục vòng chữ ký bổ sung |

**Tổ chức khác**: ISO/IEC (FrodoKEM, Classic McEliece), IETF (ML-KEM trong TLS, chứng chỉ X.509 PQC, composite signatures), ETSI, BSI (Đức), ANSSI (Pháp), NCSC (Anh), KpqC (Hàn Quốc), OSCCA (Trung Quốc có chương trình riêng).

---

## 8. Lộ trình chuyển đổi và mô hình lai (hybrid)

### 8.1. Mốc thời gian (theo dự thảo NIST IR 8547 và CNSA 2.0 của NSA)
- **Đến 2030**: các thuật toán khóa công khai lượng tử-dễ-tổn-thương ở mức an toàn 112 bit (ví dụ RSA-2048, ECC P-224...) bị **ngừng khuyến nghị (deprecated)**.
- **Đến 2035**: **cấm hoàn toàn (disallowed)** RSA, ECDSA, ECDH, DH trong hệ thống liên bang Mỹ.
- **CNSA 2.0 (NSA)**: yêu cầu hệ thống an ninh quốc gia ưu tiên PQC cho ký phần mềm/firmware, trình duyệt, mạng... và hoàn tất chuyển đổi khoảng năm 2033–2035.

### 8.2. Mô hình lai (Hybrid)
Kết hợp **một thuật toán cổ điển + một thuật toán PQC**, hệ thống chỉ bị phá khi **cả hai** cùng bị phá:

```
K = KDF( K_ECDH ‖ K_ML-KEM ‖ transcript )
```

Ví dụ: **X25519MLKEM768** trong TLS 1.3 – đã được bật mặc định trong Chrome, Firefox, Cloudflare, và nhiều hệ thống khác.

### 8.3. Crypto-agility (Linh hoạt mật mã)
Thiết kế hệ thống để có thể **thay thuật toán mà không phải viết lại toàn bộ**:
1. **Kiểm kê mật mã (cryptographic inventory)**: xác định nơi dùng RSA/ECC.
2. **Đánh giá rủi ro** theo vòng đời dữ liệu (định lý Mosca).
3. **Ưu tiên**: KEM cho dữ liệu nhạy cảm → chữ ký cho hệ thống vòng đời dài.
4. **Thử nghiệm hybrid** → triển khai dần → loại bỏ thuật toán cũ.

---

## 9. Ứng dụng thực tế hiện nay

| Lĩnh vực | Triển khai |
|---|---|
| Trình duyệt / TLS | Chrome, Edge, Firefox, Safari hỗ trợ X25519MLKEM768; Cloudflare, Google, AWS bật ở phía máy chủ |
| Nhắn tin | **Signal** (PQXDH, sau đó SPQR), **Apple iMessage** (giao thức PQ3) |
| SSH | **OpenSSH** mặc định dùng `sntrup761x25519` (từ 9.0) và `mlkem768x25519` (từ 9.9) |
| VPN | WireGuard (Rosenpass), IKEv2 (RFC 9370), các VPN thương mại |
| Thư viện | OpenSSL 3.5+ (ML-KEM, ML-DSA, SLH-DSA), BoringSSL, AWS-LC, **liboqs** (Open Quantum Safe), Bouncy Castle, PQClean |
| Phần cứng | HSM, TPM, smartcard, secure element đang bổ sung PQC |
| Hệ điều hành | Windows, Linux, Android, iOS/macOS đang tích hợp API PQC |

---

## 10. Thách thức khi triển khai

1. **Kích thước lớn**: khóa, bản mã, chữ ký lớn hơn ECC 10–100 lần → phân mảnh gói tin (TLS ClientHello, UDP/QUIC, DNSSEC), tăng băng thông, chuỗi chứng chỉ X.509 phình to.
2. **Thiết bị hạn chế tài nguyên**: IoT, thẻ thông minh có RAM/flash nhỏ.
3. **Tấn công kênh kề**: nhiều cài đặt PQC từng bị tấn công timing, power, fault → cần cài đặt **constant-time**, masking.
4. **Độ tin cậy an toàn còn trẻ**: SIKE, Rainbow bị phá sau nhiều năm → cần hybrid và đa dạng hóa.
5. **Hệ sinh thái**: PKI, HSM, chứng nhận FIPS 140-3, giao thức, phần mềm cũ (legacy) cần cập nhật đồng bộ.
6. **Nhân lực**: thiếu chuyên gia hiểu cả mật mã mới lẫn hệ thống thực tế.

---

## 11. Tài liệu tham khảo

1. NIST Post-Quantum Cryptography Project — https://csrc.nist.gov/projects/post-quantum-cryptography
2. NIST — *FIPS 203: ML-KEM*, *FIPS 204: ML-DSA*, *FIPS 205: SLH-DSA*, 08/2024.
3. NIST — *NIST IR 8545: Status Report on the Fourth Round of the NIST PQC Standardization Process*, 03/2025.
4. NIST — *NIST IR 8547 (Initial Public Draft): Transition to Post-Quantum Cryptography Standards*, 11/2024.
5. NIST — *SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes*, 2020.
6. NSA — *Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)*, 2022.
7. P. W. Shor — *Algorithms for quantum computation: discrete logarithms and factoring*, FOCS 1994.
8. L. K. Grover — *A fast quantum mechanical algorithm for database search*, STOC 1996.
9. D. J. Bernstein, T. Lange — *Post-quantum cryptography*, Nature 549, 2017.
10. W. Castryck, T. Decru — *An efficient key recovery attack on SIDH*, EUROCRYPT 2023.
11. W. Beullens — *Breaking Rainbow Takes a Weekend on a Laptop*, CRYPTO 2022.
12. M. Mosca — *Cybersecurity in an era with quantum computers: will we be ready?*, IEEE Security & Privacy, 2018.
13. Open Quantum Safe — https://openquantumsafe.org

---

*Ghi chú: Tài liệu tổng hợp cho mục đích học tập. Trạng thái chuẩn hóa và các mốc thời gian thay đổi liên tục — hãy đối chiếu với công bố mới nhất của NIST và các cơ quan liên quan.*
