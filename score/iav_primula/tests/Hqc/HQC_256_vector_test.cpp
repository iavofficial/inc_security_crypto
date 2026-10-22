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
#include "Hqc256_parameters.h"
#include "Hqc256_vector.h"
}

/**********************************************************************************************************************/
/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/
TEST(Hqc256_vector_TEST, VectResizeOutNotDivisibleBy64)
{
    uint64_t out[HQC256_VEC_N1N2_SIZE_64] = {0};
    uint64_t v[HQC256_VEC_N1N2_SIZE_64] = {0};
    const int truncated_bits = (HQC256_VEC_N1N2_SIZE_BYTES - 8) % 64;

    FsmSw_CommonLib_RandomBytes((uint8_t*)v, HQC256_VEC_N1N2_SIZE_BYTES);

    Hqc256_Vect_Resize(out, HQC256_VEC_N1N2_SIZE_BYTES - 8, v, HQC256_VEC_N1N2_SIZE_BYTES);

    EXPECT_EQ(out[HQC256_VEC_N1N2_SIZE_64 - 1] >> truncated_bits, 0);
    EXPECT_EQ(out[HQC256_VEC_N1N2_SIZE_64 - 1] & 0xffffff, v[HQC256_VEC_N1N2_SIZE_64 - 1] & 0xffffff);
}
