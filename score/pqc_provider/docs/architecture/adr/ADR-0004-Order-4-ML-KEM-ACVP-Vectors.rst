..
   # *******************************************************************************
   # Copyright (c) 2026 Contributors to the Eclipse Foundation
   #
   # See the NOTICE file(s) distributed with this work for additional
   # information regarding copyright ownership.
   #
   # This program and the accompanying materials are made available under the
   # terms of the Apache License Version 2.0 which is available at
   # https://www.apache.org/licenses/LICENSE-2.0
   #
   # SPDX-License-Identifier: Apache-2.0
   # *******************************************************************************

ADR-0004: Vendor and Exercise the Full Applicable ML-KEM ACVP Corpus
====================================================================

.. dec_rec:: Vendor and Exercise the Full Applicable ML-KEM ACVP Corpus
   :id: dec_rec__pqc_provider__kem_acvp_vectors
   :version: 2
   :status: accepted
   :context: doc__pqc_provider_architecture
   :decision: Vendor the full pinned ACVP ML-KEM key-generation and encapsulation/decapsulation projections. Exercise every case representable through the selected fixed-size liboqs API for ML-KEM-512, ML-KEM-768, and ML-KEM-1024; retain but do not pass oversized encapsulation keys to that API. Do not fetch vectors at test runtime or include Wycheproof fixtures for order 4.
   :affects: comp__pqc_provider

Context
-------

Candidate order 4 adapts liboqs' ``tests/vectors_kem.c`` for deterministic
ML-KEM-512/768/1024 key generation, encapsulation, and decapsulation checks.
The upstream ACVP wrapper obtains known-answer test cases from the
``usnistgov/ACVP-Server`` repository at tag ``v1.1.0.41``. Its test groups
provide the expected key and ciphertext outputs needed to verify those
deterministic operations. The two selected ACVP projections also provide
decapsulation-key and encapsulation-key validity groups.

The order-2 functional tests already cover ordinary operation behavior and
negative-input handling. Order 4's distinct purpose is to verify
deterministic ML-KEM outputs against external known-answer vectors. ADR-0003
has already selected local vendoring over runtime fetching; this record
determines which external corpus supplies the order-4 cases.

Decision Point
--------------

The choice is whether order 4 vendors a small ACVP subset or the full
available projections, whether to add Wycheproof vectors, and whether to fetch
the corpora dynamically. ACVP provides deterministic outputs for key
generation, encapsulation, and decapsulation, plus key-validity cases.
Dynamic fetching avoids checked-in data but adds network availability and
remote-content dependencies.

The scope is deterministic external-vector coverage for ML-KEM-512/768/1024
without expanding production algorithms or the selected order-4 test
purpose.

Decision
--------

Order 4 shall vendor both full pinned ACVP ML-KEM projection files and shall
not fetch vectors at test runtime. Exercise all 225 cases whose inputs and
expected postconditions are representable by the selected liboqs API: 75 key
generation, 75 encapsulation, 30 decapsulation, 15 valid encapsulation-key
checks, and 30 decapsulation-key checks across all three parameter sets.
Retain the 15 invalid encapsulation-key vectors whose public keys are
oversized, but do not pass them to liboqs: its encapsulation API takes a
fixed-size key pointer and has no key-length argument, so it cannot observe
their oversized lengths. Do not add Wycheproof fixtures to order 4; reconsider
that corpus only if a concrete required behavior is not covered by existing
tests or the selected ACVP cases.

Rationale
---------

Vendoring the complete two-file projection preserves all selected NIST input
data for the point when the external checkout is unavailable. Testing every
case the fixed-size liboqs API can meaningfully consume maximizes deterministic
coverage without inventing a test-only length contract. The omitted oversized
key checks belong at a length-aware caller boundary, not inside a liboqs API
that cannot receive the supplied length. Hermetic execution and order-2
ownership of broader negative-input checks remain unchanged.

Alternatives Considered
-----------------------

**Vendor only a minimal ACVP subset**

This minimizes fixture data and adaptation but discards applicable NIST
known-answer and key-check cases. It was not selected because the full
projections are manageable and the user requested inclusion of as many NIST
vectors as possible.

**Add Wycheproof fixtures**

This adds malformed-input and rejection cases, but those overlap existing
order-2 negative-input coverage and expand the selected external corpus beyond
the NIST ACVP requirement for this order. It was not selected.

**Dynamically fetch pinned vector sources**

This reuses the upstream Python wrappers and pinned repositories and avoids
checking vector bytes into this repository. It makes test execution depend
on network, TLS, remote-host availability, and external content retrieval,
and conflicts with ADR-0003's accepted offline-fixture decision.

Consequences
------------

* The complete selected ACVP JSON projections are checked in; the test
  executes all 225 cases supported by its fixed-size liboqs API boundary.
  Fifteen oversized encapsulation-key validation cases remain available in
  the raw fixtures but are not claimed as executed.
* The order-4 test must run offline and fail clearly if a local fixture is
  missing or malformed; it must not silently fall back to fetching data.
* The fixture provenance notice identifies the ACVP tag, original source
  paths, checksums, and complete redistribution notice.
* Wycheproof is not a test-execution dependency or required fixture source
  for order 4. Reconsider this exclusion if evidence identifies a required
  rejection case not covered by order 2 or ACVP.

Architecture Impact
-------------------

The order-4 test target consumes package-local ACVP fixtures and the
selected liboqs ML-KEM implementation. Test execution has no network
dependency. No production ABI, provider routing, or algorithm scope changes.

Implementation Guidance
-----------------------

Preserve both original ACVP projections without changing their cryptographic
values. Record source and checksum provenance alongside the fixtures. Adapt
upstream vector checks to use only local data and ML-KEM-512/768/1024; assert
key validity through operation status only where the API has enough input
information to do so. Keep test-only fixture handling separate from
production code.

Related Information
-------------------

* ADR-0003: Vendor liboqs Test Vectors
* ``80-integrate-liboqs/liboqs_upstream_test_candidates.md`` (candidate order 4)
* ``external/liboqs/tests/vectors_kem.c``
* ``external/liboqs/tests/test_acvp_vectors.py``
* ``external/liboqs/tests/test_wycheproof_vectors.py``
