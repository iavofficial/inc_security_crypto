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

ADR-0005: Vendor and Exercise the Full Applicable ML-DSA ACVP Corpus
====================================================================

.. dec_rec:: Vendor and Exercise the Full Applicable ML-DSA ACVP Corpus
   :id: dec_rec__iav_primula__dsa_acvp_vectors
   :version: 1
   :status: accepted
   :context: doc__iav_primula_architecture
   :decision: Vendor all three pinned ACVP ML-DSA projections and exercise all 615 key-generation, signature-generation, and signature-verification cases for ML-DSA-44, ML-DSA-65, and ML-DSA-87 offline.
   :affects: comp__iav_primula

Context
-------

Candidate order 5 adapts the ML-DSA paths from liboqs ``tests/vectors_sig.c``
and the ML-DSA cases in ``tests/test_acvp_vectors.py``. The upstream ACVP
wrapper fetches test data from ``usnistgov/ACVP-Server`` tag ``v1.1.0.41``.
The local integration must retain the fixtures because the external liboqs
checkout is not a test or runtime dependency.

The ACVP corpus provides deterministic key-generation, signature-generation,
and signature-verification cases for ML-DSA-44/65/87. Signature generation and
verification include internal ML-DSA interfaces, external pure-message
interfaces, and external pre-hash interfaces with context strings. Verification
vectors include both expected accepts and expected rejects. ADR-0003 selected
local vendoring and offline test execution for these candidates.

Decision Point
--------------

The choice is whether to vendor a subset or the full ML-DSA ACVP projections,
and whether to include only public pure-message operations or all operations
already covered by the integrated ML-DSA implementation. Runtime fetching is
not compatible with offline, checkout-independent tests. Omitting relevant
signature interfaces would leave NIST-provided cases unused despite their
implementation paths being in scope.

Decision
--------

Vendor the complete ``ML-DSA-keyGen-FIPS204``,
``ML-DSA-sigGen-FIPS204``, and ``ML-DSA-sigVer-FIPS204``
``internalProjection.json`` files from tag ``v1.1.0.41`` without modifying
their vector values. Execute all 615 cases locally: 75 key-generation, 360
signature-generation, and 180 signature-verification cases across the three
enabled parameter sets.

Use liboqs' public context-string API for external pure-message operations and
the already-integrated ML-DSA internal functions for internal-interface and
pre-hash cases. Convert ACVP message digests using the specified hash
algorithm before calling the pre-hash operations. Assert exact generated
keys/signatures and each verification vector's expected accept/reject result.
Do not add SLH-DSA cases, runtime vector fetching, or unrelated test support.

Rationale
---------

The complete projections preserve all selected NIST vectors for offline use
and remove the external repository from the test dependency graph. The ML-DSA
implementation already contains the internal and pre-hash paths used by these
vectors, so adapting the upstream runner and exposing those paths only to this
test does not expand production algorithm scope. Exercising all cases
maximizes NIST-vector coverage while keeping the test limited to the three
integrated ML-DSA parameter sets.

Alternatives Considered
-----------------------

**Vendor only key-generation and pure-message cases**

This reduces fixture size and test adaptation, but excludes in-scope ACVP
internal, pre-hash, context, and negative-verification cases. It was not
selected because those paths are already implemented and tested by the
upstream vector runner.

**Dynamically fetch the pinned projections**

This avoids checking vector data into the package but makes test execution
dependent on network access and upstream availability, contrary to ADR-0003.

**Include SLH-DSA vectors**

These test a different signature family that is outside the liboqs
integration's selected ML-KEM/ML-DSA scope. They remain excluded.

Consequences
------------

* Three unchanged NIST projections and their provenance/checksums are stored
  under ``score/iav_primula/tests/upstream/vectors/acvp/``.
* The Bazel converter validates all selected groups and emits 615 local cases;
  the test does not fetch data at build or test runtime.
* The ACVP-Server redistribution notice and NIST attribution are retained with
  the fixtures.
* The adapted test is MIT-licensed upstream-derived test code. Any updates
  must preserve source revision, case coverage, and notice/provenance records.

Architecture Impact
-------------------

The test target consumes vendored test data and the package-local ML-DSA
implementation only. Production ABI, provider routing, build integration, and
algorithm scope are unchanged.

Implementation Guidance
-----------------------

Keep the original JSON projections unchanged; validate and flatten them with
a package-local Bazel build action. Assert per-parameter-set and per-operation
case totals so a missing ACVP group cannot silently reduce the test suite.
Maintain the liboqs source revision and ACVP tag, paths, hashes, and NIST notice
in the local upstream/provenance records.

Related Information
-------------------

* ADR-0003: Vendor liboqs Test Vectors
* ``80-integrate-liboqs/liboqs_upstream_test_candidates.md`` (candidate order 5)
* ``external/liboqs/tests/vectors_sig.c``
* ``external/liboqs/tests/test_acvp_vectors.py``
