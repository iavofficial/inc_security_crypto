/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

/// @file api_header_smoke.c
/// @brief Compile-only check for the stable FFI and Automotive API headers.

// Every include below is intentional: this TU is a compile-only API-header
// smoke test, so include-cleaner cannot infer the desired coverage.
// NOLINTBEGIN(misc-include-cleaner)
#include "score/iav_primula/include/Platform_Types.h"
#include "score/iav_primula/include/iav_primula_ffi.h"

#include "FN_DSA_1024_api.h"
#include "FN_DSA_512_api.h"
#include "Hqc128_api.h"
#include "Hqc192_api.h"
#include "Hqc256_api.h"
#include "Hqc_api.h"
#include "ML_DSA_44_api.h"
#include "ML_DSA_65_api.h"
#include "ML_DSA_87_api.h"
#include "ML_KEM_1024_api.h"
#include "ML_KEM_512_api.h"
#include "ML_KEM_768_api.h"
#include "ML_KEM_api.h"
#include "SLH_DSA_SHA2_128fSimple_api.h"
#include "SLH_DSA_SHA2_128sSimple_api.h"
#include "SLH_DSA_SHA2_192fSimple_api.h"
#include "SLH_DSA_SHA2_192sSimple_api.h"
#include "SLH_DSA_SHA2_256fSimple_api.h"
#include "SLH_DSA_SHA2_256sSimple_api.h"
#include "SLH_DSA_SHAKE_128fSimple_api.h"
#include "SLH_DSA_SHAKE_128sSimple_api.h"
#include "SLH_DSA_SHAKE_192fSimple_api.h"
#include "SLH_DSA_SHAKE_192sSimple_api.h"
#include "SLH_DSA_SHAKE_256fSimple_api.h"
#include "SLH_DSA_SHAKE_256sSimple_api.h"
// NOLINTEND(misc-include-cleaner)

// These numeric literals intentionally pin the stable C ABI assignments.
// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)
_Static_assert(IavAlgorithmMlDsa44 == 1, "ML-DSA-44 ABI value changed");
_Static_assert(IavAlgorithmMlDsa65 == 2, "ML-DSA-65 ABI value changed");
_Static_assert(IavAlgorithmMlDsa87 == 3, "ML-DSA-87 ABI value changed");
_Static_assert(IavAlgorithmMlKem512 == 10, "ML-KEM-512 ABI value changed");
_Static_assert(IavAlgorithmMlKem768 == 11, "ML-KEM-768 ABI value changed");
_Static_assert(IavAlgorithmMlKem1024 == 12, "ML-KEM-1024 ABI value changed");
_Static_assert(IavAlgorithmFnDsa512 == 13, "FN-DSA-512 ABI value changed");
_Static_assert(IavAlgorithmFnDsa1024 == 14, "FN-DSA-1024 ABI value changed");
_Static_assert(IavAlgorithmSlhDsaSha2_128f == 15, "SLH-DSA-SHA2-128f ABI value changed");
_Static_assert(IavAlgorithmSlhDsaSha2_128s == 16, "SLH-DSA-SHA2-128s ABI value changed");
_Static_assert(IavAlgorithmSlhDsaSha2_192f == 17, "SLH-DSA-SHA2-192f ABI value changed");
_Static_assert(IavAlgorithmSlhDsaSha2_192s == 18, "SLH-DSA-SHA2-192s ABI value changed");
_Static_assert(IavAlgorithmSlhDsaSha2_256f == 19, "SLH-DSA-SHA2-256f ABI value changed");
_Static_assert(IavAlgorithmSlhDsaSha2_256s == 20, "SLH-DSA-SHA2-256s ABI value changed");
_Static_assert(IavAlgorithmSlhDsaShake128f == 21, "SLH-DSA-SHAKE-128f ABI value changed");
_Static_assert(IavAlgorithmSlhDsaShake128s == 22, "SLH-DSA-SHAKE-128s ABI value changed");
_Static_assert(IavAlgorithmSlhDsaShake192f == 23, "SLH-DSA-SHAKE-192f ABI value changed");
_Static_assert(IavAlgorithmSlhDsaShake192s == 24, "SLH-DSA-SHAKE-192s ABI value changed");
_Static_assert(IavAlgorithmSlhDsaShake256f == 25, "SLH-DSA-SHAKE-256f ABI value changed");
_Static_assert(IavAlgorithmSlhDsaShake256s == 26, "SLH-DSA-SHAKE-256s ABI value changed");
_Static_assert(IavAlgorithmHqc128 == 27, "HQC-128 ABI value changed");
_Static_assert(IavAlgorithmHqc192 == 28, "HQC-192 ABI value changed");
_Static_assert(IavAlgorithmHqc256 == 29, "HQC-256 ABI value changed");
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)

void primula_api_header_smoke(void) {}
