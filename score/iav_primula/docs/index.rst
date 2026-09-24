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

.. _iav_primula_component:

IAV-Primula Component
#####################

.. document:: IAV-Primula Component
   :id: doc__iav_primula
   :version: 1
   :status: invalid
   :safety: QM
   :security: YES
   :realizes: wp__cmpt_request
   :tags: iav_primula

Abstract
========

IAV-Primula is a Rust-based post-quantum cryptography backend for integration
into the S-CORE crypto component. It exposes a stable C ABI so that C++
components can invoke the backend without depending on Rust implementation
details.

The ABI currently defines operations for ML-DSA signature key management and
signing/verification as well as ML-KEM key management,
encapsulation/decapsulation, and public-key export. Status codes and algorithm
identifiers are represented by ``#[repr(C)]`` enums and are mirrored in the
public header ``include/iav_primula_ffi.h``. Private key state is represented
by an opaque ``iav_primula_key_handle`` owned by the Rust backend.

The current implementation is an integration baseline. The cryptographic
operations are exported but are not yet connected to a concrete PQC
implementation and currently return ``IavStatusUnsupportedAlgorithm``.
Resource destruction is correspondingly a no-op for the current null/stub
handles. The documented ABI is intended to remain stable while the concrete
ML-DSA and ML-KEM implementation is added.


Rationale
=========

The component establishes the integration boundary before the concrete PQC
implementation is connected. Keeping the ABI, status values, algorithm values,
and opaque handle contract stable allows the C++ integration and its tests to
progress independently from the Rust cryptographic implementation.


Specification
=============

The component currently provides the following C-compatible interface groups:

- signature key-pair generation and public-key export;
- signature generation and verification;
- KEM key-pair generation and public-key export;
- KEM encapsulation and decapsulation;
- destruction of backend-owned key handles.

The supported algorithm identifiers are ML-DSA-44, ML-DSA-65, ML-DSA-87,
ML-KEM-512, ML-KEM-768, and ML-KEM-1024. The stable status values include
successful completion, invalid arguments, insufficient output buffers,
unsupported algorithms, verification failure, and generic cryptographic
failure.

The interface is declared in ``include/iav_primula_ffi.h`` and implemented in
``src/ffi.rs``. The current implementation exposes the operation entry points
but returns ``IavStatusUnsupportedAlgorithm`` until a concrete backend is
connected.


Backwards Compatibility
=======================

No backwards compatibility impact is expected at this stage. The component is
new and currently has no consumers with compatibility constraints.


Security Impact
===============

The component defines a security-relevant FFI boundary for future PQC
operations. The current stub does not process cryptographic data, but the
interface already introduces security considerations for opaque key handles,
raw pointers, buffer lengths, algorithm selection, and error reporting.

The concrete implementation shall ensure that private key material is not
exposed through the C ABI, input pointers and lengths are validated, output
buffers are handled safely, and destroyed handles cannot be reused. The
security review must be completed before the backend performs real
cryptographic operations.


Safety Impact
=============

The component is currently classified as ``QM`` and does not implement a
safety mechanism. Nevertheless, the C ABI can affect its caller through error
codes, output buffers, and resource handles. Invalid pointers, inconsistent
lengths, unsupported algorithms, and use-after-destroyed handles must be
considered in the safety analysis and in the future implementation.

For the current stub implementation, no cryptographic result is produced and
all key-management, signature, and KEM operation entry points return
``IavStatusUnsupportedAlgorithm``. The key-destruction function is currently a
no-op for the null/stub handle. The current DFA and FMEA document the
identified FFI and resource-related risks and shall be updated when real PQC
processing and key resources are introduced.


License Impact
==============

No additional license impact is currently expected. Implementation is original
project code under Apache-2.0.


How to Teach This
=================

Integrators should use the declarations in
``include/iav_primula_ffi.h`` and treat ``iav_primula_key_handle`` as an opaque
backend-owned object. Handles returned by a future successful key-generation
operation must be released with ``iav_key_destroy()`` and must not be reused
afterwards.

The current test suite documents the integration baseline: exported
operations return ``IavStatusUnsupportedAlgorithm`` and the numeric status and
algorithm values are checked for consistency between Rust and the C ABI.

Rejected Ideas
==============

No alternatives were evaluated yet due to the intentionally small first scope.

Open Issues
===========

- Connect a concrete ML-DSA and ML-KEM implementation.
- Define and implement validation for pointers, buffer capacities, lengths, and
  algorithm identifiers.
- Define the ownership and lifecycle behavior of successful key handles,
  including failure and repeated-destruction cases.
- Define the exact public-key, signature, ciphertext, and shared-secret
  formats and their required buffer sizes.
- Integrate the Rust backend with the C++ crypto provider adapter.
- Complete the architecture, detailed design, requirements traceability, and
  review of the safety and security aspects of the implemented behavior.

Footnotes
=========

None.


Further Documentation of the component can be found in the following sections:

Component Detail Information
============================

.. toctree::
   :maxdepth: 1

   architecture/index
   detailed_design/index
   requirements/index
   safety_analysis/dfa
   safety_analysis/fmea
   safety_analysis/aou_requirements
   component_classification
