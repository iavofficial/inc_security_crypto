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

ADR-0002: IAV-Primula FFI Glue Ownership
========================================

.. dec_rec:: IAV-Primula FFI Glue Ownership
   :id: dec_rec__iav_primula__ffi_glue_ownership
   :version: 1
   :status: accepted
   :context: doc__iav_primula_architecture
   :decision: Remove the IAV-Primula Rust interface and implementation. Native, non-Rust glue shall implement the existing C ABI, own opaque key handles, and call liboqs for all supported ML-KEM and ML-DSA operations.
   :affects: comp__iav_primula

Context
-------

IAV-Primula previously exposed its C ABI and opaque key handle from Rust, with
Rust static-library and test targets in Bazel. The C++ provider consumes the
ABI. The existing header defines six variants—ML-KEM-512/768/1024 and
ML-DSA-44/65/87—and is the compatibility contract to preserve
(``score/iav_primula/include/iav_primula_ffi.h:43-51,58``). Rust owned the
FFI functions and handle implementation (``score/iav_primula/src/ffi.rs``),
and the C++ provider linked the Rust static library
(``score/crypto/src/daemon/provider/score_provider/iav_primula/BUILD:54-56``).

The required outcome is for the in-scope ML-KEM (FIPS 203) and ML-DSA
(FIPS 204) operations to actually execute via liboqs. Every operation for
these capabilities that previously returned unsupported must be implemented.
Preserve all existing C ABI names and values and support Linux and QNX on
x86_64 and aarch64. No related PRD was supplied.

Decision Point
--------------

The decision is which implementation owns the existing IAV-Primula C ABI
symbols and opaque key handles after the stubs are replaced. Retaining Rust as
the ABI/handle owner and removing Rust in favor of native glue are materially
different ownership and dependency boundaries, with different link and
maintenance costs.

Decision
--------

Remove the IAV-Primula Rust interface, implementation, and Rust target
completely. Replace the Rust FFI stubs with native, non-Rust glue to liboqs.
The native implementation owns the existing C ABI symbols and opaque
key-handle lifecycle; ``iav_primula_ffi.h`` remains the ABI contract.

The native glue must make the in-scope ML-KEM and ML-DSA operations actually
execute via liboqs for the six declared variants. No in-scope operation that
previously returned unsupported remains unsupported after integration.

Rationale
---------

Native glue directly owns and invokes the liboqs backend, satisfying the
selected removal of Rust without introducing a Rust-to-native boundary.
Although native ownership requires re-homing ABI symbols and key-handle
lifecycle and updating the provider's link dependency, it makes the ABI
implementation and cryptographic backend part of the same native integration.

Alternatives Considered
-----------------------

**Retain Rust as ABI/handle owner and call liboqs from Rust**

This follows the prior Rust static-library target and C++ consumer link path
and could replace the stubs without moving the ABI owner. It also retains the
Rust code and toolchain, introduces or maintains Rust-to-native linking and
unsafe FFI mapping across four configurations, and conflicts with the user's
instruction to remove the Rust interface.

Consequences
------------

* Remove the Rust IAV-Primula interface, implementation, and Rust Bazel
  target; do not leave Rust as ABI-symbol or key-handle owner.
* A native Bazel target implements the existing C ABI, owns opaque handles,
  and calls liboqs for all required in-scope operations and six variants.
* Preserve all names and values in ``iav_primula_ffi.h`` and the
  consumer-visible status, buffer-length, and handle behavior required by
  that contract.
* Update the C++ provider's Bazel dependency from the Rust static library to
  the native target. Provider routing remains a consumer of the ABI, not a
  substitute for cryptographic execution.
* Replace or re-home Rust-target verification so proof observes operations
  through the retained ABI/provider boundary. Verification must cover Linux
  and QNX on x86_64 and aarch64; those results remain unproven until run.

Known Unknowns and Reconsideration
----------------------------------

The exact native source language and target composition, operation-to-liboqs
mapping, ABI-compatible status/length behavior, and key-lifetime handling
require implementation design. Native Bazel builds and operation behavior
on Linux and QNX x86_64/aarch64 were not established by this decision.

Reconsider only if repository or toolchain evidence shows that native glue
cannot implement the required operations, preserve the existing C ABI, and
support all four declared configurations.

Architecture Impact
-------------------

The dependency direction becomes C++ provider → native IAV-Primula ABI
target → liboqs native Bazel targets. Rust is removed from this integration
path. The public C ABI header and its six algorithm values remain unchanged;
the native target owns both the exported ABI implementation and opaque
key-handle lifecycle.

Implementation Guidance
-----------------------

Implement the existing ABI natively and use liboqs for key generation and
export, ML-DSA signing and verification, and ML-KEM encapsulation and
decapsulation wherever these operations are declared and were unsupported.
Preserve header names, values, and existing consumer-visible ABI behavior.
Make the C++ provider depend on the native target, not a replacement Rust
wrapper. Choose the native source language and target composition from
repository patterns during implementation design; validate operation
mapping, handle lifecycle, status/length behavior, and builds for all four
configurations. Leave detailed operation mapping and test design to the
Design Doc.

Related Information
-------------------

* ``score/iav_primula/include/iav_primula_ffi.h:43-51,58``
* ``score/iav_primula/BUILD:14-36``
* ``score/iav_primula/tests/BUILD:14-21``
* ``score/crypto/src/daemon/provider/score_provider/iav_primula/BUILD:54-56``
