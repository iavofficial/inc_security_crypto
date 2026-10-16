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

IAV-Primula Requirements
########################

.. document:: IAV-Primula Requirements
   :id: doc__iav_primula_requirements
   :version: 1
   :status: invalid
   :safety: QM
   :security: YES
   :realizes: wp__requirements_comp[version==1]
   :tags: iav_primula

Scope
=====

Functional Requirements
-----------------------

.. comp_req:: Provide the stable IAV-Primula C ABI
   :id: comp_req__iav_primula__provide_c_abi
   :version: 1
   :reqtype: Interface
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__iav_primula

   The component shall provide the C-compatible interface declared in
   ``include/iav_primula_ffi.h`` and implemented by the Rust crate. Exported
   function names, parameter order, parameter types, and calling convention
   shall remain compatible with the header.

.. comp_req:: Preserve status code values
   :id: comp_req__iav_primula__stable_status_codes
   :version: 1
   :reqtype: Interface
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__iav_primula

   The numeric values of the ``iav_status`` enumeration shall be identical in
   the Rust implementation and the corresponding C header. They shall not be
   changed in a backward-incompatible release:

   - ``IavStatusOk`` = 0;
   - ``IavStatusInvalidArgument`` = 1;
   - ``IavStatusBufferTooSmall`` = 2;
   - ``IavStatusUnsupportedAlgorithm`` = 3;
   - ``IavStatusVerificationFailed`` = 4;
   - ``IavStatusCryptoFailure`` = 5.

   Rust and C declarations shall use the same names and values.

.. comp_req:: Preserve algorithm identifier values
   :id: comp_req__iav_primula__stable_algorithm_ids
   :version: 1
   :reqtype: Interface
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__iav_primula

   The component shall define the following stable algorithm identifiers and
   shall use them consistently for the corresponding operations:

   - ``IavAlgorithmMlDsa44`` = 1;
   - ``IavAlgorithmMlDsa65`` = 2;
   - ``IavAlgorithmMlDsa87`` = 3;
   - ``IavAlgorithmMlKem512`` = 10;
   - ``IavAlgorithmMlKem768`` = 11;
   - ``IavAlgorithmMlKem1024`` = 12.

   Algorithm values shall be identical in the Rust and C declarations.

Signature Operations
--------------------

.. comp_req:: Provide ML-DSA signature operations
   :id: comp_req__iav_primula__ml_dsa_operations
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   The component shall provide ``iav_keypair_generate()``,
   ``iav_public_key_export()``, ``iav_sign()``, and ``iav_verify()`` to
   generate a ML-DSA key pair, export the associated public key, sign a
   message, and verify a signature for the supported ML-DSA algorithm
   identifiers.

   A valid signature shall result in ``IavStatusOk``. An invalid signature
   shall result in ``IavStatusVerificationFailed`` and shall not be reported
   as a generic cryptographic failure.

KEM Operations
--------------

.. comp_req:: Provide ML-KEM operations
   :id: comp_req__iav_primula__ml_kem_operations
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   The component shall provide ``iav_kem_keypair_generate()``,
   ``iav_kem_public_key_export()``, ``iav_kem_encapsulate()``, and
   ``iav_kem_decapsulate()`` to generate an ML-KEM key pair, export the
   associated public key, encapsulate a shared secret, and decapsulate a
   ciphertext for the supported ML-KEM algorithm identifiers.

   Successful encapsulation and decapsulation shall return
   ``IavStatusOk``. Cryptographic processing failures shall return
   ``IavStatusCryptoFailure``.

Algorithm Validation
--------------------

.. comp_req:: Reject unsupported algorithm identifiers
   :id: comp_req__iav_primula__validate_algorithm_ids
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   Each operation shall validate the supplied algorithm identifier. An
   identifier that is not supported by the operation shall result in
   ``IavStatusUnsupportedAlgorithm`` and shall not cause key material or
   output buffers to be modified.

Key Handle Requirements
-----------------------

.. comp_req:: Keep key handles opaque
   :id: comp_req__iav_primula__opaque_key_handles
   :version: 1
   :reqtype: Interface
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   The component shall expose key objects only through the opaque
   ``iav_primula_key_handle`` type. C and C++ callers shall not depend on or
   access the internal representation of a key handle.

.. comp_req:: Manage key handle ownership
   :id: comp_req__iav_primula__key_handle_lifecycle
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   A successfully generated key handle shall be owned by the caller and shall
   be released through ``iav_key_destroy()``. The component shall release all
   backend resources associated with the handle and shall not use or expose
   private key material after destruction.

   The behavior for null, invalid, and repeatedly destroyed handles shall be
   defined and tested before successful key generation is enabled.

Pointer and Buffer Requirements
-------------------------------

.. comp_req:: Validate pointer and length parameters
   :id: comp_req__iav_primula__ptr_len
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   Each operation shall validate required pointers and associated lengths
   before accessing memory. Null pointers, inconsistent length pointers, and
   invalid buffer combinations shall result in ``IavStatusInvalidArgument``.
   The component shall not dereference invalid input pointers.

.. comp_req:: Protect caller-provided output buffers
   :id: comp_req__iav_primula__protect_output_buffers
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   For every output buffer, the corresponding length parameter shall provide
   the input capacity and receive the number of bytes written on success. The
   component shall never write beyond the supplied capacity. If the capacity
   is insufficient, the operation shall return ``IavStatusBufferTooSmall`` and
   shall not produce a truncated cryptographic result.

.. comp_req:: Handle multiple output buffers consistently
   :id: comp_req__iav_primula__multi_output
   :version: 1
   :reqtype: Interface
   :security: YES
   :safety: QM
   :status: invalid
   :satisfied_by: comp__iav_primula

   Operations with multiple output buffers, such as KEM encapsulation, shall
   validate all capacities before writing any output. A failed operation shall
   not leave a partially written ciphertext or shared secret that can be
   mistaken for a valid result.

Current Implementation Status
-----------------------------

The C ABI, status values, and algorithm values are currently implemented and
covered by tests. The key-generation, export, signature, and KEM operation
entry points are exported, but the concrete cryptographic implementation is
not connected yet and currently returns ``IavStatusUnsupportedAlgorithm``.
The current ``iav_key_destroy()`` implementation is a no-op because no valid
key handles are produced yet. The functional, handle-lifecycle, and
pointer/buffer requirements above therefore describe the required target
behavior and remain open for implementation and verification.

Assumption of Use Requirements
------------------------------

.. aou_req:: Integrate through the IAV-Primula C ABI
   :id: aou_req__iav_primula__c_abi_integration
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: valid

   The component user shall integrate IAV-Primula through the documented C ABI
   and shall include ``iav_primula_ffi.h`` that matches the linked library.

Environmental Requirements
--------------------------

.. aou_req:: Build environment supports Rust 2021
   :id: aou_req__iav_primula__rust2021_build_env
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: valid
   :tags: environment

   The component shall be built in an environment that supports Rust edition
   2021 and the Bazel Rust rules used by the component BUILD definition.

.. needextend:: "c.this_doc()"
   :+tags: iav_primula
