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

ADR-0003: Vendor liboqs Test Vectors
====================================

.. dec_rec:: Vendor liboqs Test Vectors
   :id: dec_rec__pqc_provider__vendored_test_vectors
   :version: 1
   :status: accepted
   :context: doc__pqc_provider_architecture
   :decision: Vendor only the selected external vector files and cases under score/pqc_provider/tests and run orders 4 and 5 offline; do not fetch test vectors at runtime.
   :affects: comp__pqc_provider

Context
-------

The next upstream-derived test candidates are the ML-KEM vector runner
(candidate order 4) and the ML-DSA-only vector runner (candidate order 5).
liboqs 0.16.0's ACVP wrapper fetches JSON files from the
``usnistgov/ACVP-Server`` repository at tag ``v1.1.0.41``; its Wycheproof
wrapper fetches ML-KEM/ML-DSA JSON files from ``C2SP/wycheproof`` at commit
``032b56abd1368843e4def50b4975032ec1ec7ba4``. The current
``external/liboqs`` checkout does not contain these vector files, so running
the wrappers requires network access to the upstream repositories.

The vectors are test inputs, not runtime library data. The package's
implementation and test targets are otherwise locally owned and Bazel-built.
Vector selection remains limited to ML-KEM-512/768/1024 and ML-DSA-44/65/87.

Decision Point
--------------

The question is whether orders 4 and 5 vendor their selected vectors or fetch
them dynamically from pinned upstream repositories. Vendoring increases
repository size and requires provenance/license upkeep, while pinned dynamic
fetching avoids checked-in data but makes test execution depend on network
availability and remote-host behavior.

Decision
--------

Vendor only the external vector files and cases selected for the ML-KEM and
ML-DSA tests under ``score/pqc_provider/tests``, rather than fetching vectors
at test runtime. Order-specific ADRs define which upstream sources and cases
are needed. Preserve source repository, tag/commit, source path, and a
checksum for each imported file in a local provenance manifest, and include
any required source notices or license text.

Rationale
---------

Local immutable fixtures make the cryptographic proof repeatable and
independent of upstream availability. Curating only the required cases bounds
repository growth while retaining the exact inputs used by each test. The
upstream repositories remain provenance sources, not runtime test
dependencies.

Alternatives Considered
-----------------------

**Fetch dynamically from pinned repositories**

This reuses the upstream Python wrappers and their ACVP tag and Wycheproof
commit pins and avoids checking vector data into this repository. Pins reduce
revision drift but do not remove network, TLS, cache, remote-service, or
upstream-availability dependencies; a moved or unavailable source prevents
local verification. Test contents also remain outside the consuming source
revision.

Consequences
------------

* Orders 4 and 5 can be ordinary offline Bazel tests after their fixture sets
  are selected and imported. Source and case selection may differ by
  candidate as documented in its order-specific ADR.
* Fixture updates require deliberate review of the source revision, content
  changes, checksum, and applicable notice/license terms.
* Do not add unrelated ACVP or Wycheproof algorithm families or cases to
  this partial integration.

Architecture Impact
-------------------

The vector dependency direction is from checked-in test fixtures to
package-local test targets. Test execution no longer fetches data from the
ACVP-Server or Wycheproof repositories; those repositories are retained as
provenance sources only.

Implementation Guidance
-----------------------

Select the smallest cases that exercise the accepted ML-KEM and ML-DSA
vector paths, verify redistribution terms, and record each original location
and a cryptographic checksum in a package-local manifest. Tests must read
only checked-in fixtures and must not fall back to network fetching.

Known Unknowns and Reconsideration
----------------------------------

The exact case subset and applicable source-data notice/license requirements
must be verified before fixture bytes are copied. Reconsider vendoring if
licensing prevents redistribution, the selected fixture set becomes
unreasonably large, or repository policy provides an equivalent immutable
offline-fixture mechanism.

Related Information
-------------------

* ``80-integrate-liboqs/liboqs_upstream_test_candidates.md`` (orders 4 and 5)
* ADR-0004 (order-4 source selection)
* ADR-0005 (order-5 source selection)
* ``external/liboqs/tests/test_acvp_vectors.py``
* ``external/liboqs/tests/test_wycheproof_vectors.py``
