# liboqs source provenance

## Upstream and scope

- Project: liboqs 0.16.0
- Upstream commit: `5a1a854b0dc9f2141bdc771c555ee60c37950183`
- Source: read-only checkout at `external/liboqs`.
- Copied implementation/header closure: 205 upstream-relative files, 2,361,489 bytes (2.25 MiB).
- The copied closure is exactly the common/API and ML-KEM-512/768/1024 plus ML-DSA-44/65/87 source/header set selected by `score/iav_primula/liboqs/BUILD`. No other algorithm implementation is included. The copied tree preserves upstream-relative paths and file contents/notices.
- SPDX inventory totals: 162 `Apache-2.0 OR ISC OR MIT`; 32 `MIT`; 1 `Apache-2.0 AND MIT`; 10 `not declared`.

## License text copies and selections

| Source | Package-local copy | Treatment |
|---|---|---|
| `external/liboqs/LICENSE.txt` | `score/iav_primula/liboqs/LICENSE.txt` | Upstream MIT license text; selected for `MIT` and `Apache-2.0 OR ISC OR MIT` files. |
| Repository-root `LICENSE` | `score/iav_primula/liboqs/LICENSE` | Apache-2.0 license text; retained with MIT for `Apache-2.0 AND MIT`. |
| `/usr/share/common-licenses/CC0-1.0` | `score/iav_primula/liboqs/LICENSES/CC0-1.0.txt` | CC0 1.0 Universal legal text for the eight copied XKCP files whose retained notices dedicate the work under CC0. |

`src/common/common.c` is the sole `Apache-2.0 AND MIT` file and retains both texts. Eight `not declared` XKCP files carry their CC0 dedication and URL in their source notices; the complete CC0 text is included above. `src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64-config.h` is a macro-only configuration input with no in-file license statement; its row records that limitation rather than inventing an SPDX expression, and the CC0 text is retained for its adjacent XKCP implementation sources. The remaining `not declared` file, `src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/brg_endian.h`, retains Brian Gladman's complete redistribution terms in the copied header itself; no separate license text applies to that file. Original copyright and license notices remain verbatim in all copied upstream source/header files.

## Per-file inventory

The license selection below is per copied upstream-relative source/header path. `not declared` means the file has no SPDX-License-Identifier in this pinned checkout; it is not an assertion that the file has no license or notice.

| Upstream-relative path | SPDX expression | Selected license text(s) |
|---|---|---|
| `src/common/aes/aes_ops.h` | MIT | MIT (`LICENSE.txt`) |
| `src/common/common.c` | Apache-2.0 AND MIT | Apache-2.0 (`LICENSE`) and MIT (`LICENSE.txt`) |
| `src/common/common.h` | MIT | MIT (`LICENSE.txt`) |
| `src/common/pqclean_shims/fips202.c` | MIT | MIT (`LICENSE.txt`) |
| `src/common/pqclean_shims/fips202.h` | MIT | MIT (`LICENSE.txt`) |
| `src/common/pqclean_shims/fips202x4.c` | MIT | MIT (`LICENSE.txt`) |
| `src/common/pqclean_shims/fips202x4.h` | MIT | MIT (`LICENSE.txt`) |
| `src/common/rand/rand.c` | MIT | MIT (`LICENSE.txt`) |
| `src/common/rand/rand.h` | MIT | MIT (`LICENSE.txt`) |
| `src/common/sha2/sha2_ops.h` | MIT | MIT (`LICENSE.txt`) |
| `src/common/sha3/sha3.c` | MIT | MIT (`LICENSE.txt`) |
| `src/common/sha3/sha3.h` | MIT | MIT (`LICENSE.txt`) |
| `src/common/sha3/sha3_ops.h` | MIT | MIT (`LICENSE.txt`) |
| `src/common/sha3/sha3x4.c` | MIT | MIT (`LICENSE.txt`) |
| `src/common/sha3/sha3x4.h` | MIT | MIT (`LICENSE.txt`) |
| `src/common/sha3/sha3x4_ops.h` | MIT | MIT (`LICENSE.txt`) |
| `src/common/sha3/xkcp_dispatch.h` | MIT | MIT (`LICENSE.txt`) |
| `src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-64.macros` | not declared | CC0-1.0 (`LICENSES/CC0-1.0.txt`; dedication and URL retained in source) |
| `src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-SnP.h` | not declared | CC0-1.0 (`LICENSES/CC0-1.0.txt`; dedication and URL retained in source) |
| `src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64-config.h` | not declared | No in-file license statement; CC0-1.0 text is included for the adjacent XKCP implementation, not asserted as this file's SPDX |
| `src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c` | not declared | CC0-1.0 (`LICENSES/CC0-1.0.txt`; dedication and URL retained in source) |
| `src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-unrolling.macros` | not declared | CC0-1.0 (`LICENSES/CC0-1.0.txt`; dedication and URL retained in source) |
| `src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/SnP-Relaned.h` | not declared | CC0-1.0 (`LICENSES/CC0-1.0.txt`; dedication and URL retained in source) |
| `src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/brg_endian.h` | not declared | Brian Gladman redistribution terms embedded in this file |
| `src/common/sha3/xkcp_low/KeccakP-1600times4/serial/KeccakP-1600-times4-SnP.h` | not declared | CC0-1.0 (`LICENSES/CC0-1.0.txt`; dedication and URL retained in source) |
| `src/common/sha3/xkcp_low/KeccakP-1600times4/serial/KeccakP-1600-times4-on1.c` | not declared | CC0-1.0 (`LICENSES/CC0-1.0.txt`; dedication and URL retained in source) |
| `src/common/sha3/xkcp_low/KeccakP-1600times4/serial/PlSnP-Fallback.inc` | not declared | CC0-1.0 (`LICENSES/CC0-1.0.txt`; dedication and URL retained in source) |
| `src/common/sha3/xkcp_sha3.c` | MIT | MIT (`LICENSE.txt`) |
| `src/common/sha3/xkcp_sha3x4.c` | MIT | MIT (`LICENSE.txt`) |
| `src/kem/kem.c` | MIT | MIT (`LICENSE.txt`) |
| `src/kem/kem.h` | MIT | MIT (`LICENSE.txt`) |
| `src/kem/ml_kem/kem_ml_kem.h` | MIT | MIT (`LICENSE.txt`) |
| `src/kem/ml_kem/kem_ml_kem_1024.c` | MIT | MIT (`LICENSE.txt`) |
| `src/kem/ml_kem/kem_ml_kem_512.c` | MIT | MIT (`LICENSE.txt`) |
| `src/kem/ml_kem/kem_ml_kem_768.c` | MIT | MIT (`LICENSE.txt`) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/integration/liboqs/config_c.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/integration/liboqs/fips202_glue.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/integration/liboqs/fips202x4_glue.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/cbmc.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/common.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/compress.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/compress.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/debug.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/debug.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/indcpa.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/indcpa.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/kem.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/kem.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/params.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/poly.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/poly.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/poly_k.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/poly_k.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/randombytes.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/sampling.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/sampling.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/symmetric.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/sys.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/verify.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/verify.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/zetas.inc` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/integration/liboqs/config_c.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/integration/liboqs/fips202_glue.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/integration/liboqs/fips202x4_glue.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/cbmc.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/common.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/compress.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/compress.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/debug.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/debug.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/indcpa.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/indcpa.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/kem.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/kem.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/params.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/poly.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/poly.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/poly_k.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/poly_k.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/randombytes.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/sampling.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/sampling.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/symmetric.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/sys.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/verify.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/verify.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/zetas.inc` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/integration/liboqs/config_c.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/integration/liboqs/fips202_glue.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/integration/liboqs/fips202x4_glue.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/cbmc.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/common.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/compress.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/compress.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/debug.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/debug.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/indcpa.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/indcpa.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/kem.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/kem.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/params.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/poly.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/poly.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/poly_k.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/poly_k.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/randombytes.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/sampling.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/sampling.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/symmetric.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/sys.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/verify.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/verify.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/zetas.inc` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/oqs.h` | MIT | MIT (`LICENSE.txt`) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/integration/liboqs/config_c.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/integration/liboqs/fips202_glue.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/integration/liboqs/fips202x4_glue.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/cbmc.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/common.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/ct.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/ct.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/debug.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/debug.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/packing.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/packing.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/params.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/poly.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/poly.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/poly_kl.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/poly_kl.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/polyvec.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/polyvec.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/polyvec_lazy.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/polyvec_lazy.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/randombytes.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/reduce.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/rounding.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/sign.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/sign.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/symmetric.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/sys.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/zetas.inc` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/integration/liboqs/config_c.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/integration/liboqs/fips202_glue.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/integration/liboqs/fips202x4_glue.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/cbmc.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/common.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/ct.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/ct.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/debug.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/debug.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/packing.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/packing.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/params.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/poly.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/poly.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/poly_kl.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/poly_kl.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/polyvec.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/polyvec.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/polyvec_lazy.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/polyvec_lazy.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/randombytes.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/reduce.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/rounding.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/sign.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/sign.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/symmetric.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/sys.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/zetas.inc` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/integration/liboqs/config_c.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/integration/liboqs/fips202_glue.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/integration/liboqs/fips202x4_glue.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/cbmc.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/common.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/ct.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/ct.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/debug.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/debug.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/packing.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/packing.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/params.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/poly.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/poly.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/poly_kl.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/poly_kl.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/polyvec.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/polyvec.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/polyvec_lazy.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/polyvec_lazy.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/randombytes.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/reduce.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/rounding.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/sign.c` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/sign.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/symmetric.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/sys.h` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/zetas.inc` | Apache-2.0 OR ISC OR MIT | MIT (`LICENSE.txt`; selected from the OR expression) |
| `src/sig/ml_dsa/sig_ml_dsa.h` | MIT | MIT (`LICENSE.txt`) |
| `src/sig/ml_dsa/sig_ml_dsa_44.c` | MIT | MIT (`LICENSE.txt`) |
| `src/sig/ml_dsa/sig_ml_dsa_65.c` | MIT | MIT (`LICENSE.txt`) |
| `src/sig/ml_dsa/sig_ml_dsa_87.c` | MIT | MIT (`LICENSE.txt`) |
| `src/sig/sig.c` | MIT | MIT (`LICENSE.txt`) |
| `src/sig/sig.h` | MIT | MIT (`LICENSE.txt`) |
| `src/sig_stfl/sig_stfl.h` | MIT | MIT (`LICENSE.txt`) |
