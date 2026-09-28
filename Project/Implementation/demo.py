"""Demo HQC-KEM: Alice và Bob thiết lập khóa chung, kèm đo thời gian.

Chạy:  python demo.py            (mặc định HQC-128)
       python demo.py HQC-256
       python demo.py all
"""

import sys
import time

from hqc import ALL_PARAMS, HQCKEM
from hqc import gf2x
from hqc.pke import HQCPKE


def timed(fn, *args):
    t0 = time.perf_counter()
    out = fn(*args)
    return out, (time.perf_counter() - t0) * 1000


def show_noise(params):
    """Minh họa: trọng số lỗi e' mà bộ giải mã phải sửa."""
    pke = HQCPKE(params)
    pk, sk = pke.keygen(b"\x01" * 40, b"\x02" * 40)
    m = bytes(params.k)
    ct = pke.encrypt(pk, m, b"\x03" * 32)
    trunc = (1 << params.n1n2) - 1
    noisy = ct.v ^ (gf2x.mul_sparse(ct.u, sk.y, params.n) & trunc)
    e_prime = noisy ^ pke.code.encode(m)
    print(f"  Trọng số e' = x*r2 + r1*y + e : {gf2x.weight(e_prime)} / {params.n1n2} bit"
          f"  (cận trên 2*w*wr + we = {2 * params.w * params.wr + params.we})")


def run(params):
    print(f"=== {params.name} (an toàn {params.security} bit) ===")
    kem = HQCKEM(params)

    (pk, sk), t_kg = timed(kem.keygen)
    print(f"  [Alice] KeyGen  : {t_kg:8.1f} ms | pk = {len(pk)} B, sk = {len(sk)} B")

    (ct, ss_bob), t_enc = timed(kem.encaps, pk)
    print(f"  [Bob]   Encaps  : {t_enc:8.1f} ms | ct = {len(ct)} B")

    ss_alice, t_dec = timed(kem.decaps, sk, ct)
    print(f"  [Alice] Decaps  : {t_dec:8.1f} ms")

    print(f"  Khóa chung Bob  : {ss_bob.hex()}")
    print(f"  Khóa chung Alice: {ss_alice.hex()}")
    print(f"  Khớp nhau       : {'✓' if ss_alice == ss_bob else '✗'}")
    show_noise(params)
    print()


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "HQC-128"
    targets = ALL_PARAMS.values() if arg == "all" else [ALL_PARAMS[arg.upper()]]
    for p in targets:
        run(p)


if __name__ == "__main__":
    main()
