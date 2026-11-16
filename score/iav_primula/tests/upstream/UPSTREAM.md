# Upstream-derived liboqs tests

The C test cases in this directory are adapted from liboqs 0.16.0,
commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`, under the upstream MIT
license. The corresponding source files are `tests/test_sha3.c`,
`tests/test_kem.c`, `tests/test_sig.c`, `tests/test_kem_mem.c`, and
`tests/test_sig_mem.c`; the ACVP vector test is adapted from
`tests/vectors_kem.c`. The focused test helpers derive from
`tests/test_helpers.c` and `tests/tmp_store.c`.

Adaptations keep the tests within this package's enabled SHA-3/SHAKE,
ML-KEM-512/768/1024, and ML-DSA-44/65/87 scope. Host-information printing was
removed. The generic helper was reduced to functions needed by the selected
tests, excluding its NIST KAT PRNG and stateful-signature support. The
file-store tests now use a unique directory beneath Bazel's `TEST_TMPDIR`,
require exact file lengths, run each algorithm's keygen/use/verify flow in one
test process, and remove their files and directory on completion.

The ML-KEM ACVP test vendors both original NIST `internalProjection.json`
files from `usnistgov/ACVP-Server` tag `v1.1.0.41`; their source paths,
SHA-256 checksums, and the complete source redistribution notice are recorded
in `vectors/acvp/NOTICE.md`. Test execution is fully offline. The build-time
converter validates both full projections (240 cases total) and prepares 225
cases that can be meaningfully asserted through liboqs's fixed-size KEM API:
75 key-generation, 75 encapsulation, 30 decapsulation, 15 valid
encapsulation-key-check, and 30 decapsulation-key-check cases, covering
ML-KEM-512/768/1024. The remaining 15 ACVP encapsulation-key-check cases are
negative vectors whose public keys are oversized. Since the liboqs
encapsulation API accepts a fixed-size public-key pointer without a length
argument, those length-rejection results cannot be tested through that API;
the original vectors remain vendored unchanged. The runnable key-check
operations assert their expected success/failure status.

The upstream checkout remains read-only; these adapted sources and their
Bazel target are owned by this package.
