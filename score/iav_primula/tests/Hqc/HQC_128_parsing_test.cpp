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
#include "Hqc128_parameters.h"
#include "Hqc128_parsing.h"
}

/**********************************************************************************************************************/
/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/
TEST(Hqc128_parsing_TEST, Load8ArrNotDivisibleBy8)
{
    uint64_t out[HQC128_VEC_N_SIZE_64] = {0};
    uint32 outlen = HQC128_VEC_N_SIZE_64;

    uint8_t in[15];
    uint32 inlen = sizeof(in);
    FsmSw_CommonLib_RandomBytes(in, inlen - 1);
    in[14] = 0xAAu;

    Hqc128_Load8_Arr(out, outlen, in, inlen);

    EXPECT_EQ(out[1] >> (8 * 6) & 0xffu, 0xAAu);
}
