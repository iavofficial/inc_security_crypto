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

IAV Primula Detailed Design
===========================

.. document:: IAV Primula Detailed Design
   :id: doc__iav_primula_detailed_design
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__sw_implementation
   :tags: iav_primula

Detailed Design for Component: IAV Primula
==========================================

Description
-----------

The component implementation is a C library. The stable ABI is implemented in
``src/iav_primula_ffi.c`` and the platform RNG boundary is implemented in
``src/Libs/iav_primula_rng.c`` and
``src/Libs/FsmSw_CommonLib_adapter.c``.

Design constraints:

- Keep the established public C ABI and numeric values stable.
- Keep Automotive headers private to implementation targets.
- Never substitute deterministic bytes when platform entropy is unavailable.
- Validate all lengths and capacities before calling APIs that do not accept
  buffer capacities.
- Clear key material and temporary secrets on cleanup and detected failures.

Current unit split:

- ``src/iav_primula_ffi.c``: argument validation, opaque key ownership, output
  preflight, and dispatch to selected ML-DSA/ML-KEM APIs.
- ``src/Libs/iav_primula_rng.c``: one-time provider registration and
  per-operation entropy failure tracking.
- ``src/Libs/FsmSw_CommonLib_adapter.c``: memory helper replacements and
  fail-closed random-byte forwarding; the vendor LCG source is not linked.
- ``src/ML_DSA`` and ``src/ML_KEM``: Automotive algorithm implementations.

Rationale Behind Decomposition into Units
******************************************
The stable ABI, platform entropy provider, and parameter-set implementations
are separate units because they have different ownership and security
responsibilities.

.. note:: Reason for split into multiple units could be-
	    - Based on design principles like SOLID,DRY etc
	    - Based on design pattern's etc.

Static Diagrams for Unit Interactions
-------------------------------------

A static view provides an overview of the units and their relationships using
UML 2.0 notations (e.g. class diagrams, component diagrams). Use ``.. uml::``
or ``.. image::`` directives to include the diagram.

The architecture view documents the current dependency boundary. Detailed
parameter-set internals remain in the Automotive source and are not part of
the public ABI.

Dynamic Diagrams for Unit Interactions (optional)
--------------------------------------------------

A dynamic view illustrates how the units within a component interact over their
interfaces to fulfill a specific use case or functionality. It is optional when the
component's behaviour is straightforward and can be understood from the static view
and interface documentation alone.

Use standard UML behavioural diagrams (sequence diagrams, state machine diagrams)
with ``.. uml::`` or ``.. image::`` directives.

Functional sequence and failure-path tests are tracked under M03.

Units within the Component
--------------------------

The relationship between a unit and its parent component is established implicitly
through the file path. Each component has its own directory, and units residing
within that directory belong to it. The unit's attributes and behaviour are documented
in the source code itself. A separate static diagram per unit is not required.

Interface documentation of a software unit is part of the source code (e.g. public
API headers, trait definitions, or documented function signatures).

The public C API header is the interface documentation for consumers; private
implementation contracts are described in ``80-integrate-pqc`` milestone
records.
