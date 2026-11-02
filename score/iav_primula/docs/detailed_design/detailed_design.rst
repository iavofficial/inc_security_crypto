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

IAV-Primula Detailed Design
===========================

.. document:: IAV-Primula Detailed Design
   :id: doc__iav_primula_detailed_design
   :version: 1
   :status: invalid
   :safety: QM
   :security: YES
   :realizes: wp__sw_implementation
   :tags: iav_primula

Detailed Design for Component: IAV-Primula
==========================================

Description
-----------

The implementation is currently centralized in ``src/ffi.rs`` and is exposed
to C++ through ``include/iav_primula_ffi.h``. The C ABI is deliberately kept
independent of the internal Rust representation.

The operation entry points for ML-DSA and ML-KEM are currently stubs. They are
exported with the required names and signatures but return
``IavStatusUnsupportedAlgorithm`` until a concrete PQC backend is connected.

Design constraints:

- Keep the C ABI and its numeric identifiers stable.
- Keep key handles opaque and Rust-owned.
- Validate pointer, length, and output-capacity arguments before accessing
  caller memory once the concrete backend is connected.
- Return stable ``iav_status`` values instead of exposing Rust errors or
  implementation details across the ABI.

Rationale Behind Decomposition into Units
******************************************
The unit boundaries follow the FFI and ownership boundary:

- ``include/iav_primula_ffi.h``: public C ABI declarations;
- ``src/ffi.rs``: exported ABI functions, C-compatible enums, opaque handle
  type, and status translation;
- concrete PQC backend: planned Rust-internal implementation behind the FFI
  functions and not yet connected.

Static Design View
------------------

The component architecture already shows the C++ to C-ABI to Rust FFI to PQC
backend decomposition. No additional static UML is required at the current
complexity. The detailed design focuses on the ownership and error contracts
that are not visible in the component view.

Dynamic Design View
-------------------

The relevant operation flow is:

1. A C++ caller invokes an operation declared in ``iav_primula_ffi.h``.
2. The Rust FFI entry point receives the C-compatible values.
3. The entry point validates the algorithm, handles, pointers, and buffer
   capacities.
4. The operation dispatches to the concrete ML-DSA or ML-KEM backend.
5. The result is translated into an ``iav_status`` value and output lengths
   are returned to the caller.

In the current implementation, step 3 is not yet implemented as full input
validation and step 4 is skipped because no backend is connected. The
operation returns ``IavStatusUnsupportedAlgorithm``.

FFI Representation
------------------

The exported functions use ``extern "C"`` and ``#[no_mangle]`` so that their
symbols and calling convention match the declarations in the C header. The
``iav_status`` and ``iav_algorithm`` enums use ``#[repr(C)]`` and fixed
discriminant values that must remain synchronized with the C declarations.

The ``iav_primula_key_handle`` type is opaque. Its representation is private
to Rust and callers may only pass its pointer to the defined ABI functions.

Ownership and Key-Handle Lifecycle
-----------------------------------

Successful key-generation functions will return ownership of an opaque key
handle to the caller through their output pointer. The caller shall release
the handle using ``iav_key_destroy()`` and shall not use it afterwards. The
destroy operation shall release all Rust/backend resources associated with the
handle without exposing private key material.

The behavior for null, invalid, and repeatedly destroyed handles must be
defined before successful key generation is enabled. Until then, key
generation returns ``IavStatusUnsupportedAlgorithm`` and
``iav_key_destroy()`` is a no-op.

Error and Buffer Handling
-------------------------

The ABI reports failures through ``iav_status``. ``IavStatusInvalidArgument``
is used for invalid pointers, handles, or inconsistent length parameters.
Unsupported or invalid algorithm values result in
``IavStatusUnsupportedAlgorithm``. ``IavStatusBufferTooSmall`` is used when
an output buffer cannot hold the complete result. ``IavStatusVerificationFailed``
denotes an invalid signature, while ``IavStatusCryptoFailure`` denotes a
cryptographic processing failure.

Output length parameters are treated as input capacities and output lengths.
The implementation shall validate all output capacities before writing and
shall never write beyond a caller-provided buffer. Operations with multiple
outputs, such as KEM encapsulation, shall not leave partially written output
that could be mistaken for a valid result after a failure.

The current stub does not dereference the supplied buffers or handles and
returns ``IavStatusUnsupportedAlgorithm`` for the cryptographic operations.

Units within the Component
--------------------------

The relationship between a unit and its parent component is established implicitly
through the file path. Each component has its own directory, and units residing
within that directory belong to it. The unit's attributes and behaviour are documented
in the source code itself. A separate static diagram per unit is not required.

Interface documentation of a software unit is part of the source code (e.g. public
API headers, trait definitions, or documented function signatures).

Current unit list:

- ``src/ffi.rs``: current Rust implementation and exported C ABI symbols;
- ``include/iav_primula_ffi.h``: C/C++ interface declaration;
- concrete PQC implementation: not yet present or connected.
