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

AoU Component Requirements Snippets
===================================

This page contains the current Assumptions of Use snippets used by IAV Primula.

Component AoU
-------------

.. code-block:: rst

   .. aou_req:: Register a reviewed platform random-byte provider
      :id: aou_req__iav_primula__platform_rng
      :reqtype: Process
      :security: YES
      :safety: QM
      :status: valid

      The integrator shall register a reviewed, cryptographically secure,
      thread-safe random-byte callback before invoking key generation or KEM
      encapsulation. The callback and its context shall remain valid for the
      lifetime of the process.

   .. aou_req:: Build environment supports the C implementation
      :id: aou_req__iav_primula__c_build_env
      :reqtype: Process
      :security: YES
      :safety: QM
      :status: valid
      :tags: environment

      The component shall be built with a C compiler and Bazel toolchain that
      support C11 atomics and thread-local storage.
