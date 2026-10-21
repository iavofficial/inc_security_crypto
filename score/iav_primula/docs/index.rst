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

.. _iav_primula_component:

IAV Primula Component
#####################

.. note:: Document header

.. document:: IAV Primula Component
   :id: doc__iav_primula
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__cmpt_request
   :tags: iav_primula

Abstract
========

IAV Primula is a C library that integrates the PQCleanAutomotive post-quantum
cryptographic implementation behind the stable C ABI in
``include/iav_primula_ffi.h``. The public interface provides signature key
management, detached signatures, and key encapsulation operations without
exposing Automotive implementation headers to C++ consumers.

The current FFI glue implements ML-DSA-44/65/87 and ML-KEM-512/768/1024.
Additional parameter sets are planned in the integration milestones. Key
generation and KEM encapsulation require a platform cryptographically secure
random-byte provider to be registered before use. No default entropy source is
provided; this checkout does not yet integrate a reviewed platform provider,
so production use remains blocked until one is supplied and validated.


Rationale
=========

The integration keeps the existing C ABI and implements it as a Bazel C
library. Automotive sources and headers remain private implementation details;
only the stable FFI header is intended for external C/C++ consumers.

.. note::
   The rationale should provide evidence of consensus within the community and discuss important objections or concerns raised during discussion.
   For the documentation of the decision the :need:`gd_temp__change_decision_record` can be used.

Specification
=============

The public interface is declared in ``include/iav_primula_ffi.h``. Bazel
consumers link ``//score/iav_primula:iav_primula`` or
``//score/iav_primula:iav_primula_staticlib`` and depend separately on
``//score/iav_primula:iav_primula_ffi_headers`` for the stable header.
Algorithms outside the current ML-DSA/ML-KEM glue scope return
``IavStatusUnsupportedAlgorithm`` until their integration milestone is
complete.


Backwards Compatibility
=======================

Existing status and algorithm numeric values and existing function signatures
are retained. Additional algorithm identifiers and the one-time RNG-provider
registration function are additive ABI extensions.


Security Impact
===============

This component performs security-critical cryptographic operations. The
Automotive algorithms call a common random-byte interface whose source
implementation uses a deterministic LCG; that source is excluded from the
active build. A project-owned adapter fails closed when no platform provider is
registered or when a provider request fails, and the glue discards and clears
temporary results on detected entropy errors.

The current checkout has no reviewed platform RNG registered by the crypto
provider. Consequently, ML-DSA/ML-KEM key generation and ML-KEM encapsulation
return ``IavStatusCryptoFailure`` until an integrator supplies a reviewed,
thread-safe platform provider. The target compiler, allocator behavior, and
secure-clear implementation also require validation on the deployment MCU.

.. note::
   If there are security concerns in relation to the CR, those concerns should be explicitly written out to make sure reviewers of the CR are aware of them.

Which security requirements are affected or has to be changed?
Could the new/modified component enable new threat scenarios?
Could the new/modified component enable new attack paths?
Could the new/modified component impact functional safety?
If applicable, which additional security measures must be implemented to mitigate the risk?

.. note::
   Use Security Software Critically Analysis, Vulnerability Analysis.
   [Methods will be defined later in Process area Security Analysis]


Safety Impact
=============

No safety impact is identified for the current scope. The component is
classified as ``QM`` and currently does not implement safety mechanisms.

.. note::
   If there are safety concerns in relation to the CR, those concerns should be explicitly written out to make sure reviewers of the CR are aware of them.

Which safety requirements are affected or has to be changed?
Could the new/modified component be a potential common cause or cascading failure initiator?
If applicable, which additional safety measures must be implemented to mitigate the risk?

.. note::
   Use Dependency Failure Analysis and/or Safety Software Critically Analysis.
   [Methods will be defined later in Process area Safety Analysis]

For new feature/component contributions:

- Expected ASIL level: ``QM``
- Expected classification of the contribution: preliminary ``Q``

.. note::
   Use the component classification method here to classify your component, if it shall to be used in a safety context: :need:`gd_temp__component_classification`.

License Impact
==============

No additional license impact is currently expected. Implementation is original
project code under Apache-2.0.


How to Teach This
=================

Include ``iav_primula_ffi.h``, register the platform RNG during initialization,
and call the stable FFI through the public Bazel C library. Functional
algorithm coverage and edge-case tests are tracked in M03.

.. note::
   For a CR that adds new functionality or changes behaviour, it is helpful to include a section on how to teach users, new and experienced, how to apply the CR to their work.

Rejected Ideas
==============

No alternatives were evaluated yet due to the intentionally small first scope.

.. note::
   Throughout the discussion of a CR, various ideas will be proposed which are not accepted.
   Those rejected ideas should be recorded along with the reasoning as to why they were rejected.
   This both helps record the thought process behind the final version of the CR as well as preventing people from bringing up the same rejected idea again in subsequent discussions.
   In a way this section can be thought of as a breakout section of the Rationale section that is focused specifically on why certain ideas were not ultimately pursued.



Open Issues
===========

- Integrate and review a target-specific entropy provider.
- Implement the remaining FN-DSA, SLH-DSA, and HQC FFI glue.
- Validate the allocator and C11 atomic/thread-local requirements on the target.
- Add functional GTests for algorithm round trips and FFI edge cases.
- Confirm if safety analysis artifacts are required once safety-relevant
  behavior is introduced.

.. note::
   While a CR is in draft, ideas can come up which warrant further discussion.
   Those ideas should be recorded so people know that they are being thought about but do not have a concrete resolution.
   This helps make sure all issues required for the CR to be ready for consideration are complete and reduces people duplicating prior discussion.



Footnotes
=========

None.


Further Documentation of the component can be found in the following sections:

Component Detail Information
============================

.. toctree::
   :maxdepth: 1

   architecture/index
   detailed_design/index
   requirements/index
   safety_analysis/dfa
   safety_analysis/fmea
   safety_analysis/aou_requirements_template
   component_classification
   ../src/README
