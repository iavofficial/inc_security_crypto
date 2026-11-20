# Task: Provider consumption of the native IAV-Primula ABI

Metadata:

- Source Plan Tasks: [P2-T1]
- Dependencies: `docs/plans/tasks/20261114-work-iav-primula-liboqs-task-01.md`

## Implementation Outcome

Link the IAV-Primula provider to `//score/pqc_provider:pqc_provider_staticlib` while preserving provider routing, complete the three supplied provider test skeletons as runnable tests of the specified ML-KEM and ML-DSA operations, and update the adjacent application integration test's sign/verify initialization fixtures to use valid provider-generated keys.

## Governing Sources

- `docs/design/iav-primula-liboqs-design.md` — Acceptance Criteria (AC-003); Change Surface; Components and Flow; Contracts, State, and Persistence; Verification Strategy.
- `score/pqc_provider/docs/architecture/adr/ADR-0002-IAV-Primula-FFI-Glue-Ownership.rst` — Decision; Consequences; Implementation Guidance.

## Target Files

- `score/crypto/src/daemon/provider/score_provider/pqc_provider/BUILD`
- `score/crypto/src/daemon/provider/score_provider/pqc_provider/tests/pqc_provider_key_management_test.cpp` — complete this supplied test skeleton unchanged in path.
- `score/crypto/src/daemon/provider/score_provider/pqc_provider/tests/pqc_provider_signature_test.cpp` — complete this supplied test skeleton unchanged in path.
- `score/crypto/src/daemon/provider/score_provider/pqc_provider/tests/pqc_provider_verification_test.cpp` — complete this supplied test skeleton unchanged in path.
- `score/crypto/src/daemon/provider/score_provider/pqc_provider/tests/integration_tests/pqc_provider_application_integration_test.cpp` — replace invalid sentinel handles in the existing sign/verify initialization integration tests with provider-generated keys.

## Investigation Targets

- `docs/design/iav-primula-liboqs-design.md` — the governing sections cited above.
- `score/pqc_provider/docs/architecture/adr/ADR-0002-IAV-Primula-FFI-Glue-Ownership.rst` — the governing sections cited above.
- `score/crypto/src/daemon/provider/score_provider/pqc_provider/BUILD` — current provider dependency.
- `score/crypto/src/daemon/provider/score_provider/pqc_provider/key_management/pqc_provider_key_factory.cpp` — provider key generation, import, encapsulation, and decapsulation paths.
- `score/crypto/src/daemon/provider/score_provider/pqc_provider/operations/sign/pqc_provider_sign_handler.cpp` and `score/crypto/src/daemon/provider/score_provider/pqc_provider/operations/verify/pqc_provider_verify_handler.cpp` — existing provider operation paths.
- The three target test files — supplied provider test skeletons and their existing assertions.
- `score/crypto/src/daemon/provider/score_provider/pqc_provider/tests/integration_tests/pqc_provider_application_integration_test.cpp` — adjacent sign/verify handler-initialization integration coverage and its provider-generated-key fixtures.
- `score/crypto/src/daemon/provider/score_provider/pqc_provider/tests/integration_tests/BUILD` — existing integration test target and Bazel label.
- `score/pqc_provider/include/pqc_provider_ffi.h` — ABI consumed by the provider; preserve its contract.

## Investigation Notes

- The provider library currently links `//score/pqc_provider:pqc_provider_staticlib_staticlib`; its key factory, sign handler, and verify handler already call the existing ABI. Key generation dispatches to the KEM or signature ABI functions, and signing validates the algorithm, bound handle, and output capacity before calling `iav_sign`. Verification uses the generated native handle or the imported key's raw public bytes; `IavStatusVerificationFailed` maps to `false`. The C ABI declarations and numeric values remain unchanged.
- The key factory's ML-KEM encapsulation path requires a public-key handler with `kAgree`, while decapsulation requires the generated private-key handle with `kAgree`. The provider test therefore exports the generated key's public bytes, imports them with `kAgree`, encapsulates to that imported key, and decapsulates with the generated private key. Both paths return `IavPrimulaSharedSecretHandler`, which records `kSharedSecret` material with `kDerive` permissions and rejects `Export`; tests can assert these properties without inspecting secret bytes.
- The supplied tests currently retain placeholder expectations: ML-KEM key generation expects unsupported; signing with a fake sentinel handle expects execution failure; imported verification uses synthetic bytes and expects execution failure; and a second fake-signature verification expects execution failure. Design AC-003 and Task 02 steps 3–4 replace these with successful ML-KEM-768 encapsulation/decapsulation plus derive-only, non-exportable handles; successful ML-DSA-44 signing after argument checks; `true` for generated/imported-key verification; and `false` for an invalid signature. Preserve sign argument-validation and wrong-actor checks, and use real IAV-generated keys/signatures instead of sentinel handles for backend-reaching operations. `IavPrimulaKeyHandler` destruction calls `iav_key_destroy` for every non-null handle, so replace sentinel pointers throughout these test files, using real generated handles where initialization succeeds and null handles where validation rejects before backend use.
- The adjacent `tests/integration_tests/pqc_provider_application_integration_test.cpp` also binds non-null `0x1` handles in its sign/verify initialization checks. Its handler destructors own those handles, so this test would pass an invalid pointer to the now-real `iav_key_destroy`; use real provider-generated keys there as well to keep the existing integration target runnable.
- Provider routes/operation handlers and the three existing Bazel test targets are already present. Only the provider dependency and the affected tests need changes; `quality.yaml` is absent. The repository's clang-tidy hook excludes `*_test.cpp`, so the changed provider C++ tests require clang-format but are not in the configured clang-tidy scope.

## Implementation Steps

1. Read the investigation targets and confirm the provider's existing ABI routing and the three test targets.
2. Replace the provider's Rust static-library Bazel dependency with `//score/pqc_provider:pqc_provider_staticlib`; do not reroute or replace provider operations.
3. Complete the tests to prove ML-KEM-768 encapsulation and decapsulation return derive-only, non-exportable shared-secret handles; ML-DSA-44 signing succeeds after retaining pre-backend argument checks; valid signatures verify through both the generated key and an imported copy of its exported public bytes; and an invalid signature returns `false`.
4. Replace placeholder-backend expectations rather than adding artificial backend-failure injection. Keep ABI shared-secret byte equality proof in the ABI test from the dependency task.
5. Update the adjacent `pqc_provider_application_integration_test.cpp` sign/verify initialization cases to use provider-generated keys instead of non-null `0x1` sentinels. `IavPrimulaKeyHandler` owns every non-null handle and its destruction calls `Release()`, which now calls the real `iav_key_destroy`; the sentinels are invalid handles. Preserve the handler-initialization integration coverage using valid generated keys.
6. Run both provider and application integration test commands below, and apply repository formatting/static-analysis rules to changed provider C++ files.

## Operation Verification Methods

- **Verification method**: Run `bazel test --config=x86_64-linux //score/crypto/src/daemon/provider/score_provider/pqc_provider/tests:pqc_provider_key_management_test //score/crypto/src/daemon/provider/score_provider/pqc_provider/tests:pqc_provider_signature_test //score/crypto/src/daemon/provider/score_provider/pqc_provider/tests:pqc_provider_verification_test`.
- **Success criteria**: All three provider tests pass and observe successful ML-KEM-768 encapsulation/decapsulation with derive-only non-exportable shared-secret handles; successful ML-DSA-44 signing with argument validation retained; `true` for valid generated-key and imported-public-key verification; and `false` for an invalid signature.
- **Verification level**: L2 integration.
- **Verification method**: Run `bazel test --config=x86_64-linux //score/crypto/src/daemon/provider/score_provider/pqc_provider/tests/integration_tests:pqc_provider_application_integration_test`.
- **Success criteria**: The application integration target passes with its sign/verify handler-initialization coverage using valid provider-generated keys instead of invalid non-null sentinel handles.
- **Provider-code quality**: Apply repository `.clang-format` and `.clang-tidy` rules to changed provider C++ files.

## Verification Focus

- **Primary failure**: Provider operations still fail at the native backend boundary, return incorrectly typed or exportable KEM secrets, reject a valid generated/imported-key signature, or map an invalid signature to an execution error.
- **Observable check**: The three provider tests assert successful ML-KEM-768 encapsulation/decapsulation and derive-only non-exportable shared-secret handles; successful ML-DSA-44 signing with argument validation retained; `true` for valid generated-key and imported-public-key verification; and `false` for an invalid signature.

## Completion Criteria

- [ ] The provider links to the native ABI target and continues to consume the existing ABI without changing provider routing.
- [ ] The three supplied test files are runnable provider tests proving AC-003 at the provider boundary.
- [ ] Placeholder-backend expectations are replaced without artificial backend-failure injection or provider-visible KEM secret-byte comparisons.
- [ ] The specified provider Bazel test command passes and Verification Focus is satisfied.
