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
#include "Hqc128_vector.h"
}

/**********************************************************************************************************************/
/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/
TEST(Hqc128_vector_TEST, VectResizeOutNotDivisibleBy64)
{
    uint64_t out[HQC128_VEC_N1N2_SIZE_64] = {0};
    uint64_t v[HQC128_VEC_N1N2_SIZE_64] = {0};
    const int truncated_bits = (HQC128_VEC_N1N2_SIZE_BYTES - 8) % 64;

    FsmSw_CommonLib_RandomBytes((uint8_t*)v, HQC128_VEC_N1N2_SIZE_BYTES);

    Hqc128_Vect_Resize(out, HQC128_VEC_N1N2_SIZE_BYTES - 8, v, HQC128_VEC_N1N2_SIZE_BYTES);

    // size_o % 64 == 24
    EXPECT_EQ(out[HQC128_VEC_N1N2_SIZE_64 - 1] >> truncated_bits, 0);
    EXPECT_EQ(out[HQC128_VEC_N1N2_SIZE_64 - 1] & 0xffffff, v[HQC128_VEC_N1N2_SIZE_64 - 1] & 0xffffff);
}
