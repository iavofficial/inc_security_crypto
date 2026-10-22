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

#include "FsmSw_Fips202.h"

FAKE_VOID_FUNC3(FsmSw_Fips202_Shake128_Absorb, shake128ctx*, const uint8_t*, uint32)
FAKE_VOID_FUNC3(FsmSw_Fips202_Shake128_SqueezeBlocks, uint8_t*, uint32, shake128ctx*)
FAKE_VOID_FUNC2(FsmSw_Fips202_Shake128_CtxClone, shake128ctx*, const shake128ctx*)
FAKE_VOID_FUNC1(FsmSw_Fips202_Shake128_IncInit, shake128incctx*)
FAKE_VOID_FUNC3(FsmSw_Fips202_Shake128_IncAbsorb, shake128incctx*, const uint8_t*, uint32)
FAKE_VOID_FUNC1(FsmSw_Fips202_Shake128_IncFinalize, shake128incctx*)
FAKE_VOID_FUNC3(FsmSw_Fips202_Shake128_IncSqueeze, uint8_t*, uint32, shake128incctx*)
FAKE_VOID_FUNC2(FsmSw_Fips202_Shake128_IncCtxClone, shake128incctx*, const shake128incctx*)

FAKE_VOID_FUNC2(FsmSw_Fips202_Shake256_CtxClone, shake256ctx*, const shake256ctx*)
FAKE_VOID_FUNC1(FsmSw_Fips202_Shake256_IncInit, shake256incctx*)
FAKE_VOID_FUNC3(FsmSw_Fips202_Shake256_IncAbsorb, shake256incctx*, const uint8_t*, uint32)
FAKE_VOID_FUNC1(FsmSw_Fips202_Shake256_IncFinalize, shake256incctx*)
FAKE_VOID_FUNC3(FsmSw_Fips202_Shake256_IncSqueeze, uint8_t*, uint32, shake256incctx*)
FAKE_VOID_FUNC2(FsmSw_Fips202_Shake256_IncCtxClone, shake256incctx*, const shake256incctx*)

FAKE_VOID_FUNC4(FsmSw_Fips202_Shake128, uint8_t*, uint32, const uint8_t*, uint32)
FAKE_VOID_FUNC4(FsmSw_Fips202_Shake256, uint8_t*, uint32, const uint8_t*, uint32)

FAKE_VOID_FUNC1(FsmSw_Fips202_Sha3_256_IncInit, sha3_256incctx*)
FAKE_VOID_FUNC3(FsmSw_Fips202_Sha3_256_IncAbsorb, sha3_256incctx*, const uint8_t*, uint32)
FAKE_VOID_FUNC2(FsmSw_Fips202_Sha3_256_IncFinalize, uint8_t*, sha3_256incctx*)
FAKE_VOID_FUNC2(FsmSw_Fips202_Sha3_256_IncCtxClone, sha3_256incctx*, const sha3_256incctx*)
FAKE_VOID_FUNC3(FsmSw_Fips202_Sha3_256, uint8_t*, const uint8_t*, uint32)
FAKE_VOID_FUNC1(FsmSw_Fips202_Sha3_384_IncInit, sha3_384incctx*)
FAKE_VOID_FUNC3(FsmSw_Fips202_Sha3_384_IncAbsorb, sha3_384incctx*, const uint8_t*, uint32)
FAKE_VOID_FUNC2(FsmSw_Fips202_Sha3_384_IncFinalize, uint8_t*, sha3_384incctx*)
FAKE_VOID_FUNC2(FsmSw_Fips202_Sha3_384_IncCtxClone, sha3_384incctx*, const sha3_384incctx*)
FAKE_VOID_FUNC3(FsmSw_Fips202_Sha3_384, uint8_t*, const uint8_t*, uint32)
FAKE_VOID_FUNC1(FsmSw_Fips202_Sha3_512_IncInit, sha3_512incctx*)
FAKE_VOID_FUNC3(FsmSw_Fips202_Sha3_512_IncAbsorb, sha3_512incctx*, const uint8_t*, uint32)
FAKE_VOID_FUNC2(FsmSw_Fips202_Sha3_512_IncFinalize, uint8_t*, sha3_512incctx*)
FAKE_VOID_FUNC2(FsmSw_Fips202_Sha3_512_IncCtxClone, sha3_512incctx*, const sha3_512incctx*)
FAKE_VOID_FUNC3(FsmSw_Fips202_Sha3_512, uint8_t*, const uint8_t*, uint32)
