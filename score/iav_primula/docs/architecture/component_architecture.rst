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

.. document:: IAV Primula Architecture
   :id: doc__iav_primula_architecture
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__component_arch
   :tags: iav_primula


Overview
--------

IAV Primula is a Bazel C library. It exposes the stable C ABI in
``include/iav_primula_ffi.h`` and keeps PQCleanAutomotive headers private to
the implementation targets. The active glue maps ML-DSA and ML-KEM FFI
operations to the corresponding Automotive parameter-set APIs.

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

The implementation is divided into three responsibilities:

- FFI glue validates arguments, owns opaque key handles, and maps vendor
  results and buffer sizes to stable status values.
- PQCleanAutomotive provides the parameter-set cryptographic implementations.
- The project-owned CommonLib adapter supplies memory helpers and delegates
  random-byte requests to the registered platform callback.

Design constraints:

- Preserve all existing FFI status and algorithm values.
- Do not provide a deterministic or implicit RNG fallback.
- Check capacities before writing outputs and do not publish partial results.
- Keep secret key material and temporary shared secrets securely cleared when
  released by the glue.

Rationale Behind Architecture Decomposition
*******************************************

The decomposition separates the stable ABI and key lifecycle from the
algorithm implementation and platform entropy boundary.

.. note:: Common decisions across components / cross cutting concepts is at the higher level.

Static Architecture
-------------------

The components are designed to cover the expectations from the feature architecture
(i.e. if already exists a definition it should be taken over and enriched).

A component can optional also consist of lower level components to further structure the architecture. The component and its static views can also optionally use interfaces provided by other components.

.. comp:: IAV Primula
   :id: comp__iav_primula
   :version: 1
   :security: YES
   :safety: QM
   :status: valid
   :belongs_to: feat__mtef

.. comp_arc_sta:: IAV Primula Static View
   :id: comp_arc_sta__iav_primula__sv
   :version: 1
   :security: YES
   :safety: QM
   :status: valid
   :belongs_to: comp__iav_primula
   :fulfils: comp_req__iav_primula__provide_c_ffi

   .. needarch::
      :scale: 50
      :align: center

      {{ draw_component(need(), needs) }}

Dynamic Architecture
--------------------

.. comp_arc_dyn:: IAV Primula Dynamic View
   :id: comp_arc_dyn__iav_primula__dv
   :version: 1
   :security: YES
   :safety: QM
   :status: valid
   :belongs_to: comp__iav_primula
   :fulfils: comp_req__iav_primula__provide_c_ffi

   A caller registers the platform RNG during initialization. For key
   generation or KEM encapsulation, the FFI starts per-operation entropy error
   tracking, calls the Automotive implementation, and publishes outputs only
   if every random-byte request succeeds. Without a provider or after a
   provider error, the operation returns ``IavStatusCryptoFailure`` and does
   not publish the generated key or cryptographic outputs.

Interfaces
----------

.. real_arc_int:: Stable IAV Primula C ABI
   :id: real_arc_int__iav_primula__c_ffi
   :version: 1
   :security: NO
   :safety: QM
   :status: valid
   :language: cpp

Internal Components
-------------------

The Automotive implementation is an internal dependency and is not exposed
through the public C++ dependency surface.

.. note::
   Architecture can be split into multiple files. At component level the public interfaces to be used by the user and tester to be shown.
