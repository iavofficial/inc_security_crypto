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

IAV-Primula Safety Assumptions of Use
=====================================

.. document:: IAV-Primula Safety Assumptions of Use
   :id: doc__iav_primula_safety_aou
   :version: 1
   :status: invalid
   :safety: QM
   :security: YES
   :realizes: wp__requirements_comp_aou
   :tags: iav_primula

These Assumptions of Use apply when IAV-Primula is integrated through its C
ABI. They define responsibilities of the component user at the boundary where
the C++ caller supplies pointers, lengths, buffers, algorithms, and key-handle
lifecycle operations.

Safety Assumptions of Use
-------------------------

.. aou_req:: Use a matching IAV-Primula C ABI header
   :id: aou_req__iav_primula__safety_matching_c_abi
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: invalid

   The component user shall compile against the ``iav_primula_ffi.h`` header
   belonging to the linked IAV-Primula library and shall not modify the
   declared function signatures, enum values, or opaque handle type.

.. aou_req:: Supply valid pointers and buffer capacities
   :id: aou_req__iav_primula__valid_buffers
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: invalid

   The component user shall provide valid pointers and consistent lengths for
   all required input and output parameters. Output buffers shall provide the
   capacity specified by the corresponding length parameter, and callers shall
   not access an output unless the operation returned ``IavStatusOk``.

.. aou_req:: Use key handles only through the defined lifecycle
   :id: aou_req__iav_primula__handle_lifecycle
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: invalid

   The component user shall treat ``iav_primula_key_handle`` as opaque, shall
   pass handles only to operations that accept them, and shall call
   ``iav_key_destroy()`` exactly as defined by the component. A handle shall
   not be used after destruction.

.. aou_req:: React to IAV-Primula status codes
   :id: aou_req__iav_primula__safety_status_handling
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: invalid

   The component user shall check the returned ``iav_status`` value before
   consuming output data and shall implement an explicit error reaction for
   invalid arguments, insufficient buffers, unsupported algorithms,
   verification failure, and cryptographic failure.

.. aou_req:: Use only supported algorithm identifiers
   :id: aou_req__iav_primula__supported_algs
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: invalid

   The component user shall select only the algorithm identifiers supported by
   the invoked operation and shall handle ``IavStatusUnsupportedAlgorithm``
   without treating the operation as successful.

Implementation Status
---------------------

The current implementation returns ``IavStatusUnsupportedAlgorithm`` for the
cryptographic operations and does not yet create valid key handles. These
assumptions become operationally relevant when the concrete PQC backend and
resource lifecycle are enabled.
