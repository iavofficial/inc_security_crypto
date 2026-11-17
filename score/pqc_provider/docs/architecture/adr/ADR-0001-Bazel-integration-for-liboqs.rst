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

ADR-0001: Bazel Integration for liboqs
======================================

.. dec_rec:: Bazel Integration for liboqs
   :id: dec_rec__pqc_provider__bazel
   :version: 1
   :status: accepted
   :context: doc__pqc_provider_architecture
   :decision: Build the partial liboqs integration with native Bazel targets over the required source closure copied into score/pqc_provider/liboqs. Do not use a foreign CMake build or source references into external/liboqs.
   :affects: comp__pqc_provider

Context
-------

PQC Provider must perform the requested ML-KEM (FIPS 203) and ML-DSA (FIPS 204)
operations using liboqs as the actual cryptographic provider. The partial
integration is limited to those two algorithm families and their six declared
variants, and must build for Linux and QNX on x86_64 and aarch64. Preserve the
existing PQC Provider C ABI. Copy required upstream files and own their Bazel
declarations under ``score/pqc_provider``; do not write under
``external/``. Outside that package, limit build edits to removing obsolete
liboqs-only root/MODULE wiring and updating the provider dependency; preserve
unrelated targets and declarations.

The repository has native Bazel target patterns and declares both ``rules_cc``
and ``rules_foreign_cc`` (``MODULE.bazel:31-32,50``). SoftHSM demonstrates
foreign CMake integration with QNX-specific environments
(``third_party/soft_hsm/BUILD:15-22,54-66``). Upstream liboqs is a C/ASM CMake
project whose CMake configuration selects sources and generates configuration
headers (``external/liboqs/CMakeLists.txt:302-312`` and
``external/liboqs/src/CMakeLists.txt:91-100``). The read-only checkout is
liboqs 0.16.0 at commit ``5a1a854b0dc9f2141bdc771c555ee60c37950183``; its
``LICENSE.txt`` describes the general MIT license and warns that some included
modules have separate licenses.

An earlier implementation used workspace-root wrappers and exposed
``external/liboqs`` through a local repository
(``score/pqc_provider/BUILD:23-159``, root ``BUILD:55-175``, and
``MODULE.bazel:37-46``). Direct root-package source labels under ``external/``
failed because Bazel reserves that execution-root path. That observation
motivated the local-repository workaround; it did not establish that copying
was unnecessary or satisfy the later requirement that the copied source and
its Bazel ownership reside inside ``score/pqc_provider``.

Decision Point
--------------

The choice is how to build the partial liboqs dependency while keeping the
copied sources and their build ownership inside the PQC Provider package.
Vendored native-Bazel sources, a local-repository mapping to the checkout, and
a foreign CMake build have materially different source ownership, dependency
direction, configuration, and lifecycle costs.

The supported scope is ML-KEM-512/768/1024 and ML-DSA-44/65/87 for Linux and
QNX on x86_64 and aarch64. This decision does not change the PQC Provider
ABI-glue ownership selected by ADR-0002.

Decision
--------

Use the repository's native Bazel target structure for a partial integration
of only the liboqs components needed by PQC Provider. Do not use
``rules_foreign_cc`` or a foreign CMake build for this partial integration.

Copy only the liboqs common/API closure and the six selected variant
source/header groups from the recorded upstream revision into
``score/pqc_provider/liboqs/``. Put their native Bazel declarations in
``score/pqc_provider/liboqs/BUILD``. Have ``score/pqc_provider/BUILD`` consume
the package-local ``liboqs_partial`` target and expose its PQC Provider-owned
``oqsconfig.h`` to that subpackage with narrow visibility.

Rationale
---------

Native Bazel over an in-package vendored closure is selected because the
required source and build ownership must reside below ``score/pqc_provider``.
This keeps the partial dependency visible in the consuming package, avoids
root-package wrappers and a Bzlmod mapping back to ``external/``, and lets
Bazel build only the selected closure. It intentionally accepts the
source-copy, update, and license-provenance costs.

Alternatives Considered
-----------------------

**Native Bazel via ``new_local_repository`` over ``external/liboqs``**

This avoids duplicating upstream source and keeps the checkout read-only, but
requires root-level metadata and wrappers and leaves Bazel declarations away
from the consuming package. It conflicts with the explicit in-package
source/build-ownership requirement. The workaround solves the reserved
``external/`` path problem but does not satisfy that requirement.

**Upstream CMake through ``rules_foreign_cc``**

This reuses upstream source selection and generated configuration headers and
fits an existing repository integration pattern, including QNX environments.
It also adds foreign-build configuration, declared outputs, and a foreign
build boundary for this limited partial integration. It does not match the
selected native-Bazel boundary.

Consequences
------------

* The PQC Provider dependency graph uses native Bazel targets defined in
  ``score/pqc_provider/liboqs/BUILD``; the PQC Provider package depends on that
  in-package partial target.
* The copied closure contains only the common/API inputs and six ML-KEM and
  ML-DSA variants. ``score/pqc_provider/liboqs/UPSTREAM.md`` records the
  source revision and copied paths. Retain upstream notices, ``LICENSE.txt``,
  and applicable component-specific licenses.
* ``external/liboqs`` remains a read-only provenance/source input, not a
  Bazel source repository for this integration. Remove only the liboqs
  local-repository registration from ``MODULE.bazel`` and its source/header
  wrappers from the root ``BUILD``, preserving unrelated entries.
* Copying creates a manual upstream-update obligation. Keep the copy bounded
  to the selected closure and update its provenance and license material with
  any future source refresh.
* Build verification must cover Linux and QNX on x86_64 and aarch64. Local
  verification covers x86_64-Linux and aarch64-Linux; the user's separate
  external-server step owns the two QNX checks. This record does not assert
  that all four configurations have passed.
* ``rules_foreign_cc`` remains available for other repository integrations;
  this decision excludes it only for the partial liboqs integration.

Architecture Impact
-------------------

The data/build path is ``external/liboqs`` (read-only source provenance) →
the copied common/API and six-variant closure under
``score/pqc_provider/liboqs/`` → native Bazel targets owned by
``score/pqc_provider/liboqs/BUILD`` → the PQC Provider package's ABI target. The
PQC Provider-owned ``oqsconfig.h`` enables only the two family API gates and six
selected variant macros. This decision does not change the public
``pqc_provider_ffi.h`` contract or the ABI-glue owner selected by ADR-0002.

Known Unknowns and Reconsideration
----------------------------------

The exact transitive source closure and target composition require
implementation and build proof. Linux builds for x86_64 and aarch64 are
required locally; QNX source/compiler/toolchain behavior remains for the
user's separate external-server checks. The current source mapping is not
evidence that all four configurations build.

Reconsider this decision if the in-package copy/build-ownership requirement
changes, if applicable licensing cannot be satisfied, or if build evidence
shows that the selected native closure cannot deliver the six required
variants. Preserve the six-variant, no-foreign-build, and no-write-under-
``external/`` constraints unless their owner changes them.

Implementation Guidance
-----------------------

Copy only the transitive source/header closure needed by the six variants
from liboqs 0.16.0 commit ``5a1a854b0dc9f2141bdc771c555ee60c37950183`` into
``score/pqc_provider/liboqs/``, preserving upstream-relative paths and source
notices. Include ``LICENSE.txt`` and applicable component-specific license
text; record the upstream version, commit, and copied paths in
``score/pqc_provider/liboqs/UPSTREAM.md``. Add package-local ``BUILD``
declarations, isolate per-variant compile definitions, expose one partial
target to ``score/pqc_provider/BUILD``, and expose the package-owned
configuration header with package-scoped visibility.

Remove only the liboqs local-repository registration from ``MODULE.bazel``
and its wrappers from the root ``BUILD``. Keep the Bazel-owned configuration
header limited to the two family gates and six selected variant macros. Do
not write under ``external/`` or use a foreign build. Verify both Linux
configurations locally and leave QNX verification to the user's separate
external-server step.

Related Information
-------------------

* ``MODULE.bazel:31-32,50``
* ``score/pqc_provider/BUILD:14-160``
* ``score/pqc_provider/liboqs/BUILD`` and
  ``score/pqc_provider/liboqs/UPSTREAM.md``
* ``third_party/soft_hsm/BUILD:15-22,54-66``
* ``external/liboqs/CMakeLists.txt:302-312``
* ``external/liboqs/src/CMakeLists.txt:91-100``
* ``external/liboqs/LICENSE.txt``
