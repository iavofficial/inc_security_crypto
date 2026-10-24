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

IAV Primula Requirements
########################

.. document:: IAV Primula Requirements
   :id: doc__iav_primula_requirements
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__requirements_comp[version==1]
   :tags: iav_primula

Scope
=====

Functional Requirements
-----------------------

.. comp_req:: Provide the stable C cryptographic interface
   :id: comp_req__iav_primula__provide_c_ffi
   :version: 1
   :reqtype: Functional
   :security: NO
   :safety: ASIL_B
   :status: valid
   :satisfied_by: comp__iav_primula

   The component shall provide the public C functions declared by
   ``include/iav_primula_ffi.h`` and preserve the numeric values of existing
   status and algorithm identifiers.

Assumption of Use Requirements
------------------------------

.. aou_req:: Register a reviewed platform random-byte provider
   :id: aou_req__iav_primula__platform_rng
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: valid

   The integrator shall register a reviewed, cryptographically secure,
   thread-safe random-byte callback before invoking key generation or KEM
   encapsulation. The callback and its context shall remain valid for the
   lifetime of the process. The callback shall return success only after
   filling the complete requested buffer.

Environmental Requirements
--------------------------

.. aou_req:: Build environment supports the C implementation
   :id: aou_req__iav_primula__c_build_env
   :version: 1
   :reqtype: Process
   :security: YES
   :safety: QM
   :status: valid
   :tags: environment

   The component shall be built with a C compiler and Bazel toolchain that
   support the C11 atomics and thread-local storage used by RNG registration
   and per-operation error tracking.

.. needextend:: "c.this_doc()"
   :+tags: iav_primula
