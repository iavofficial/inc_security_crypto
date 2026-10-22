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

/**********************************************************************************************************************/
/* INCLUDES                                                                                                           */
/**********************************************************************************************************************/
#include <gtest/gtest.h>

extern "C" {
#include "FsmSw_CommonLib.h"
#include "SLH_DSA_SHA2_256fSimple_hash.h"
#include "SLH_DSA_SHA2_256fSimple_params.h"
#include "crc32.h"
}

/**********************************************************************************************************************/
/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/
TEST(SLH_DSA_SHA2_256fSimple_hash_sha2_TEST, Mgf512LongOutput)
{
    uint8_t out[SLH_DSA_SHA512_OUTPUT_BYTES + 8];
    uint32 outlen = sizeof(out);
    uint8_t seed[64] = {0};
    uint32 inlen = sizeof(seed);
    FsmSw_CommonLib_RandomBytes(seed, inlen);
    const uint32_t expected_crc32_out = 0x423c224e;

    SLH_DSA_SHA2_256fSimple_MgF1_512(out, outlen, seed, inlen);

    uint32_t crc32_out = crc32(out, outlen);
    EXPECT_EQ(expected_crc32_out, crc32_out);
}
