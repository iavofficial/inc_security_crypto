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
#include "fff_helper.hpp"
#include <gtest/gtest.h>

extern "C" {
#include "FsmSw_CommonLib.h"
#include "ML_DSA_87_poly.h"
#include "fake_fips202.h"
}

/**********************************************************************************************************************/
/* HELP FUNCTIONS                                                                                                     */
/**********************************************************************************************************************/
void shake256_inc_squeeze_large_output(uint8_t* output, uint32 outlen, shake256incctx* state)
{
    for (int ix = 0; ix < outlen; ix++)
    {
        output[ix] = 255;
    }
}

void shake256_inc_squeeze_small_output(uint8_t* output, uint32 outlen, shake256incctx* state)
{
    for (int ix = 0; ix < outlen; ix++)
    {
        output[ix] = 128;
    }
}

/**********************************************************************************************************************/
/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/
TEST(ML_DSA_87_poly_TEST, PolyUniformSmallCtr)
{
    poly_D5 c;
    uint8_t seed[CTILDEBYTES_ML_DSA_87];

    FsmSw_CommonLib_RandomBytes(seed, CTILDEBYTES_ML_DSA_87);

    FsmSw_Fips202_Shake256_IncSqueeze_Fakefunc_T func_seq[2] = {shake256_inc_squeeze_large_output,
                                                                shake256_inc_squeeze_small_output};
    SET_CUSTOM_FAKE_SEQ(FsmSw_Fips202_Shake256_IncSqueeze, func_seq, 2);

    ML_DSA_87_Poly_Challenge(&c, seed);

    EXPECT_EQ(FsmSw_Fips202_Shake256_IncSqueeze_fake.call_count, 2);
    RESET_FAKE(FsmSw_Fips202_Shake256_IncSqueeze);
}

TEST(ML_DSA_87_poly_TEST, PolyChknormBTooLarge)
{
    poly_D5 polynomial;
    int largeB = 1047552;  // ((Q - 1) / 8)) + 1

    int retVal = ML_DSA_87_Poly_Chknorm(&polynomial, largeB);

    EXPECT_EQ(retVal, 1);
}
