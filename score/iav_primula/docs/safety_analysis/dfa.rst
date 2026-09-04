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


DFA (Dependent Failure Analysis)
================================

.. document:: IAV-Primula DFA
   :id: doc__iav_primula_dfa
   :version: 1
   :status: invalid
   :safety: QM
   :security: YES
   :realizes: wp__sw_component_dfa
   :tags: iav_primula

The component is currently classified as ``QM`` and the cryptographic backend
is not connected. Nevertheless, the FFI boundary is analysed because invalid
caller inputs and backend failures can affect the behavior of the consuming
C++ component once the PQC implementation is enabled.

Dependent Failure Initiators
----------------------------

.. comp_saf_dfa:: Invalid pointer or length at the C ABI boundary
   :violates: comp_arc_sta__iav_primula__sv
   :id: comp_saf_dfa__iav_primula__ptr_len
   :version: 1
   :failure_id: EX_01_01
   :failure_effect: An invalid pointer or inconsistent length is dereferenced or processed, causing corrupted output, a crash, or an incorrect result in the consuming component.
   :mitigated_by: comp_req__iav_primula__ptr_len
   :sufficient: no
   :status: invalid

   The FFI implementation shall reject invalid pointer and length combinations
   before accessing caller memory. The current stub does not dereference these
   inputs because it returns ``IavStatusUnsupportedAlgorithm`` first.

.. comp_saf_dfa:: Output buffer boundary violation
   :violates: comp_arc_sta__iav_primula__sv
   :id: comp_saf_dfa__iav_primula__buf_boundary
   :version: 1
   :failure_id: CO_01_02
   :failure_effect: A public key, signature, ciphertext, or shared secret is written beyond the caller-provided output capacity, corrupting adjacent memory and potentially causing an unsafe system state.
   :mitigated_by: comp_req__iav_primula__protect_output_buffers
   :sufficient: no
   :status: invalid

   Output capacities shall be checked before writing and insufficient buffers
   shall result in ``IavStatusBufferTooSmall`` without a truncated result.

.. comp_saf_dfa:: Inconsistent error status
   :violates: comp_arc_sta__iav_primula__sv
   :id: comp_saf_dfa__iav_primula__error_status
   :version: 1
   :failure_id: EX_01_01
   :failure_effect: A failure is reported with an incorrect status code, causing the caller to treat invalid or incomplete cryptographic output as valid or to perform an incorrect error reaction.
   :mitigated_by: comp_req__iav_primula__stable_status_codes
   :sufficient: no
   :status: invalid

   Rust and C shall use the same status values and distinguish invalid
   arguments, insufficient buffers, verification failure, unsupported
   algorithms, and cryptographic failure.

.. comp_saf_dfa:: Key resource not released
   :violates: comp_arc_sta__iav_primula__sv
   :id: comp_saf_dfa__iav_primula__key_resource
   :version: 1
   :failure_id: EX_01_04
   :failure_effect: A key handle or backend resource remains allocated or is reused after destruction, exhausting resources or causing use-after-destroyed-handle behavior.
   :mitigated_by: comp_req__iav_primula__key_handle_lifecycle
   :sufficient: no
   :status: invalid

   ``iav_key_destroy()`` shall release all resources associated with a valid
   handle. Null, invalid and repeated destruction behavior remains to be
   defined and tested.

.. comp_saf_dfa:: Cryptographic backend failure
   :violates: comp_arc_sta__iav_primula__sv
   :id: comp_saf_dfa__iav_primula__crypto_failure
   :version: 1
   :failure_id: EX_01_01
   :failure_effect: A PQC operation fails or returns an invalid result, while the caller receives a success indication or an output that cannot be trusted.
   :mitigated_by: comp_req__iav_primula__ml_dsa_operations, comp_req__iav_primula__ml_kem_operations
   :sufficient: no
   :status: invalid

   Backend failures shall be translated to ``IavStatusCryptoFailure`` and
   failed operations shall not expose incomplete cryptographic results. The
   current implementation has no connected backend and returns
   ``IavStatusUnsupportedAlgorithm`` instead.
