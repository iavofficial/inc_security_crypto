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


FMEA (Failure Modes and Effects Analysis)
=========================================

.. document:: IAV-Primula FMEA
   :id: doc__iav_primula_fmea
   :version: 1
   :status: invalid
   :safety: QM
   :security: YES
   :realizes: wp__sw_component_fmea
   :tags: iav_primula

The component is currently classified as ``QM`` and the concrete PQC backend
is not connected. The FMEA nevertheless records the relevant failure modes of
the defined C ABI and the expected backend integration. The entries remain
``draft`` until the implementation and safety requirements have been verified.

Failure Mode List
-----------------

.. list-table:: Fault Models for sequence diagrams
    :header-rows: 1
    :widths: 10,20,10,20

    * - ID
      - Failure Mode
      - Applicability
      - Rationale
    * - MF_01_01
      - message is not received (is a subset/more precise description of MF_01_05)
      - no
      - No inter-component messaging in current scope.
    * - MF_01_02
      - message received too late (only relevant if delay is a realistic fault)
      - no
      - No timing-critical communication path in current scope.
    * - MF_01_03
      - message received too early (usually not a problem)
      - no
      - No timing-dependent message protocol is implemented.
    * - MF_01_04
      - message not received correctly by all recipients (different messages or messages partly lost). Only relevant if the same message goes to multiple recipients.
      - no
      - No fan-out message distribution exists.
    * - MF_01_05
      - message is corrupted
      - no
      - No message transport layer in current scope.
    * - MF_01_06
      - message is not sent
      - no
      - No send operation is implemented.
    * - MF_01_07
      - message is unintended sent
      - no
      - Component does not emit external messages.
    * - CO_01_01
      - minimum constraint boundary is violated
      - no
      - No numerical safety boundary handling in current scope.
    * - CO_01_02
      - maximum constraint boundary is violated
      - yes
      - Output buffer capacity can be smaller than the required public-key, signature, ciphertext, or shared-secret size.
    * - EX_01_01
      - Process calculates wrong result(s) (subset of data corruption faults)
      - yes
      - A PQC backend can fail or return an invalid result; the FFI must not report success for an untrusted result.
    * - EX_01_02
      - processing too slow (only relevant if timing is considered)
      - no
      - No timing requirement allocated to current baseline function.
    * - EX_01_03
      - processing too fast (only relevant if timing is considered)
      - no
      - No minimum timing constraint allocated.
    * - EX_01_04
      - loss of execution
      - yes
      - A failed or interrupted cleanup operation can leave key resources allocated or allow an invalid handle lifecycle.
    * - EX_01_05
      - processing changes to arbitrary process
      - no
      - No process control behavior is implemented.
    * - EX_01_06
      - processing is not complete (infinite loop)
      - no
      - Function body is finite and constant.

FMEA
----

.. comp_saf_fmea:: Invalid pointer or length
   :violates: comp_arc_sta__iav_primula__sv
   :id: comp_saf_fmea__iav_primula__ptr_len
   :version: 1
   :fault_id: EX_01_01
   :failure_effect: Invalid memory access or incorrect processing can cause a crash, corrupted output, or an unsafe caller reaction.
   :mitigated_by: comp_req__iav_primula__ptr_len
   :sufficient: no
   :status: invalid

   The implementation shall validate required pointers and associated lengths
   before accessing memory. The current stub does not access the supplied
   memory because all cryptographic operations return unsupported.

.. comp_saf_fmea:: Output buffer too small
   :violates: comp_arc_sta__iav_primula__sv
   :id: comp_saf_fmea__iav_primula__buf_small
   :version: 1
   :fault_id: CO_01_02
   :failure_effect: Output truncation or an out-of-bounds write can corrupt memory or produce a result that the caller incorrectly treats as valid.
   :mitigated_by: comp_req__iav_primula__protect_output_buffers, comp_req__iav_primula__multi_output
   :sufficient: no
   :status: invalid

   The implementation shall check all output capacities before writing and
   shall return ``IavStatusBufferTooSmall`` without a partial result.

.. comp_saf_fmea:: Incorrect status code
   :violates: comp_arc_sta__iav_primula__sv
   :id: comp_saf_fmea__iav_primula__error_status
   :version: 1
   :fault_id: EX_01_01
   :failure_effect: The caller may apply an incorrect error reaction or use invalid cryptographic output if a failure is reported with the wrong status code.
   :mitigated_by: comp_req__iav_primula__stable_status_codes
   :sufficient: no
   :status: invalid

   Status values shall be stable between Rust and C and shall distinguish
   invalid arguments, buffer exhaustion, verification failure, unsupported
   algorithms, and cryptographic failure.

.. comp_saf_fmea:: Key resource leak or use after destruction
   :violates: comp_arc_sta__iav_primula__sv
   :id: comp_saf_fmea__iav_primula__key_lifecycle
   :version: 1
   :fault_id: EX_01_04
   :failure_effect: A leaked or reused key resource can exhaust resources, expose stale state, or cause an invalid cryptographic operation.
   :mitigated_by: comp_req__iav_primula__key_handle_lifecycle
   :sufficient: no
   :status: invalid

   Successful key handles shall be released through ``iav_key_destroy()``.
   Null, invalid, and repeated destruction behavior must be specified and
   tested before key generation is enabled.

.. comp_saf_fmea:: Cryptographic operation failure
   :violates: comp_arc_sta__iav_primula__sv
   :id: comp_saf_fmea__iav_primula__crypto_failure
   :version: 1
   :fault_id: EX_01_01
   :failure_effect: A failed signature, verification, encapsulation, or decapsulation operation can result in an incorrect security or safety decision.
   :mitigated_by: comp_req__iav_primula__ml_dsa_operations, comp_req__iav_primula__ml_kem_operations
   :sufficient: no
   :status: invalid

   Backend failures shall be reported as ``IavStatusCryptoFailure`` and shall
   not be confused with a valid result. Invalid signatures shall be reported
   as ``IavStatusVerificationFailed``.
