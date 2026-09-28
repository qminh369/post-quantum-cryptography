"""HQC.KEM – cơ chế đóng gói khóa an toàn IND-CCA2.

Dựng từ HQC.PKE bằng biến đổi Fujisaki-Okamoto (biến thể HHK) với
từ chối ngầm (implicit rejection) và salt:

    Encaps(pk):
        m <- ngẫu nhiên, salt <- ngẫu nhiên
        theta = G(H(pk) || m || salt)
        c     = PKE.Encrypt(pk, m; theta)
        K     = K(m || c || salt)
    Decaps(sk, (c, salt)):
        m'    = PKE.Decrypt(sk, c)
        c'    = PKE.Encrypt(pk, m'; G(H(pk) || m' || salt))
        K     = K(m' || c || salt)     nếu c' == c
              = K(sigma || c || salt)  ngược lại

Định dạng:
    pk = seed_pk (40) || s
    sk = seed_sk (40) || sigma (k) || pk
    ct = u || v || salt (16)
"""

import hmac
import secrets

from .params import HQC_128, HQCParams
from .pke import HQCPKE
from .xof import DOMAIN_G, DOMAIN_H, DOMAIN_K, shake


class HQCKEM:
    def __init__(self, params: HQCParams = HQC_128):
        self.p = params
        self.pke = HQCPKE(params)

    # Các hàm băm có tách miền
    def _H(self, pk_bytes: bytes) -> bytes:
        return shake(DOMAIN_H, pk_bytes, outlen=32)

    def _G(self, pk_hash: bytes, m: bytes, salt: bytes) -> bytes:
        return shake(DOMAIN_G, pk_hash, m, salt, outlen=32)

    def _K(self, m: bytes, ct_body: bytes, salt: bytes) -> bytes:
        return shake(DOMAIN_K, m, ct_body, salt, outlen=self.p.SS_BYTES)

    # ----------------------------------------------------------------- keygen
    def keygen(self, seed: bytes | None = None) -> tuple[bytes, bytes]:
        """Sinh (pk, sk). Truyền `seed` (≥ 1 byte) để sinh tất định khi kiểm thử."""
        p = self.p
        if seed is None:
            seed_sk = secrets.token_bytes(p.SEED_BYTES)
            seed_pk = secrets.token_bytes(p.SEED_BYTES)
            sigma = secrets.token_bytes(p.k)
        else:
            material = shake(b"\x00", seed, outlen=2 * p.SEED_BYTES + p.k)
            seed_sk = material[: p.SEED_BYTES]
            seed_pk = material[p.SEED_BYTES: 2 * p.SEED_BYTES]
            sigma = material[2 * p.SEED_BYTES:]

        pk, _ = self.pke.keygen(seed_sk, seed_pk)
        pk_bytes = self.pke.pk_to_bytes(pk)
        sk_bytes = seed_sk + sigma + pk_bytes
        return pk_bytes, sk_bytes

    # ----------------------------------------------------------------- encaps
    def encaps(self, pk_bytes: bytes, m: bytes | None = None,
               salt: bytes | None = None) -> tuple[bytes, bytes]:
        """Trả về (ciphertext, shared_secret)."""
        p = self.p
        pk = self.pke.pk_from_bytes(pk_bytes)
        m = secrets.token_bytes(p.k) if m is None else m
        salt = secrets.token_bytes(p.SALT_BYTES) if salt is None else salt

        theta = self._G(self._H(pk_bytes), m, salt)
        ct_body = self.pke.ct_to_bytes(self.pke.encrypt(pk, m, theta))
        return ct_body + salt, self._K(m, ct_body, salt)

    # ----------------------------------------------------------------- decaps
    def decaps(self, sk_bytes: bytes, ct_bytes: bytes) -> bytes:
        p = self.p
        if len(sk_bytes) != p.sk_bytes:
            raise ValueError("Độ dài khóa bí mật không hợp lệ")
        if len(ct_bytes) != p.ct_bytes:
            raise ValueError("Độ dài bản mã không hợp lệ")

        seed_sk = sk_bytes[: p.SEED_BYTES]
        sigma = sk_bytes[p.SEED_BYTES: p.SEED_BYTES + p.k]
        pk_bytes = sk_bytes[p.SEED_BYTES + p.k:]
        ct_body, salt = ct_bytes[: -p.SALT_BYTES], ct_bytes[-p.SALT_BYTES:]

        sk = self.pke.expand_sk(seed_sk)
        pk = self.pke.pk_from_bytes(pk_bytes)

        m_prime, _ = self.pke.decrypt(sk, self.pke.ct_from_bytes(ct_body))

        # Mã hóa lại và so sánh (so sánh thời gian hằng)
        theta = self._G(self._H(pk_bytes), m_prime, salt)
        ct_check = self.pke.ct_to_bytes(self.pke.encrypt(pk, m_prime, theta))
        ok = hmac.compare_digest(ct_check, ct_body)

        k_accept = self._K(m_prime, ct_body, salt)
        k_reject = self._K(sigma, ct_body, salt)
        return k_accept if ok else k_reject
