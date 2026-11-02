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

Component Architecture Documentation
====================================

.. document:: IAV-Primula Architecture
   :id: doc__iav_primula_architecture
   :version: 1
   :status: invalid
   :safety: QM
   :security: YES
   :realizes: wp__component_arch
   :tags: iav_primula


Overview
--------

IAV-Primula is a Rust-based post-quantum cryptography backend. Its public
integration boundary is a C ABI consumed by C++ code. The component separates
the C ABI from the Rust FFI implementation and is intended to connect that
implementation to a concrete ML-DSA/ML-KEM backend.

The current implementation contains the C ABI declarations and the Rust FFI
entry points. The concrete PQC backend is not connected yet; the cryptographic
entry points therefore return ``IavStatusUnsupportedAlgorithm``.

Requirements Linked to Component Architecture
---------------------------------------------

.. code-block:: none

   .. needtable:: Overview of Component Requirements
      :style: table
      :columns: title;id
      :filter: search("comp_arch_sta__archdes$", "fulfils_back")
      :colwidths: 70,30

Description
-----------

The component is decomposed into the following architectural elements:

- the C ABI header ``include/iav_primula_ffi.h``;
- the Rust FFI layer in ``src/ffi.rs``;
- the PQC backend behind the FFI layer, which is planned but not yet
  integrated.

The Bazel targets provide both a Rust library and a Rust static library. The C
header is provided as a separate public target for C++ integration.

Design constraints:

- Keep the C ABI stable and independent of Rust implementation details.
- Keep status-code and algorithm identifiers identical between Rust and C.
- Keep key handles opaque to C++ callers and independent of the Rust implementation.
- Validate pointers, lengths, and output capacities before accessing memory.
- Keep private key material inside the Rust/backend boundary.

Rationale Behind Architecture Decomposition
*******************************************

The decomposition follows the language and ownership boundaries. The C ABI
defines the externally visible contract, the Rust FFI layer translates calls
into Rust-owned types and operations, and the PQC backend performs the actual
cryptographic processing. Keeping these responsibilities separate allows the
backend implementation to evolve without changing the C ABI.

Static Architecture
-------------------

.. comp:: IAV-Primula
   :id: comp__iav_primula
   :version: 1
   :security: YES
   :safety: QM
   :status: valid
   :belongs_to: feat__mtef
   :consists_of: comp__iav_primula_c_abi,
      comp__iav_primula_rust_ffi,
      comp__iav_primula_pqc_backend

.. comp_arc_sta:: IAV-Primula Static View
   :id: comp_arc_sta__iav_primula__sv
   :version: 1
   :security: YES
   :safety: QM
   :status: invalid
   :belongs_to: comp__iav_primula

   .. needarch::
      :scale: 50
      :align: center

      {{ draw_component(need(), needs) }}

Dynamic Architecture
--------------------

.. comp_arc_dyn:: IAV-Primula Dynamic View
   :id: comp_arc_dyn__iav_primula__dv
   :version: 1
   :security: YES
   :safety: QM
   :status: invalid
   :belongs_to: comp__iav_primula
   :fulfils: comp_req__iav_primula__ml_dsa_operations,
      comp_req__iav_primula__ml_kem_operations,
      comp_req__iav_primula__validate_algorithm_ids,
      comp_req__iav_primula__ptr_len,
      comp_req__iav_primula__protect_output_buffers

   A C++ caller invokes one of the functions declared in
   ``iav_primula_ffi.h``. The call crosses the C ABI into the Rust FFI layer
   implemented in ``src/ffi.rs``. The Rust layer shall validate the call
   contract and dispatch the operation to the selected PQC backend. The
   current implementation returns before backend dispatch because no concrete
   backend is connected, so cryptographic operations return
   ``IavStatusUnsupportedAlgorithm``.

Interfaces
----------

.. real_arc_int:: IAV-Primula C ABI
   :id: real_arc_int__iav_primula__c_abi
   :version: 1
   :security: YES
   :safety: QM
   :status: invalid
   :language: cpp

   The C ABI provides signature operations ``iav_keypair_generate()``,
   ``iav_public_key_export()``, ``iav_sign()``, and ``iav_verify()`` as well
   as KEM operations ``iav_kem_keypair_generate()``,
   ``iav_kem_public_key_export()``, ``iav_kem_encapsulate()``, and
   ``iav_kem_decapsulate()``. Key handles are released with
   ``iav_key_destroy()``. Status and algorithm identifiers are part of the
   interface contract.

Internal Components
-------------------

.. comp:: C ABI Boundary
   :id: comp__iav_primula_c_abi
   :version: 1
   :security: YES
   :safety: QM
   :status: valid
   :belongs_to: feat__mtef

   The public header ``iav_primula_ffi.h`` defines the C-compatible function
   signatures, enums, and opaque key-handle type used by C++ callers.

.. comp:: Rust FFI Layer
   :id: comp__iav_primula_rust_ffi
   :version: 1
   :security: YES
   :safety: QM
   :status: valid
   :belongs_to: feat__mtef

   The Rust implementation in ``src/ffi.rs`` exports the C ABI symbols,
   maintains the Rust-side types, and translates the backend result into the
   stable ``iav_status`` values.

.. comp:: PQC Backend
   :id: comp__iav_primula_pqc_backend
   :version: 1
   :security: YES
   :safety: QM
   :status: valid
   :belongs_to: feat__mtef

   The PQC backend shall provide the concrete ML-DSA and ML-KEM operations.
   It is not connected in the current implementation; the FFI entry points
   currently return ``IavStatusUnsupportedAlgorithm``.
