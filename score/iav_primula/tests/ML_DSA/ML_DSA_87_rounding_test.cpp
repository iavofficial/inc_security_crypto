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
#include "ML_DSA_87_rounding.h"
}

/**********************************************************************************************************************/
/* DEFINES                                                                                                            */
/**********************************************************************************************************************/
#define RET_ERR 1

/**********************************************************************************************************************/
/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/
TEST(ML_DSA_87_rounding_TEST, MakeHintWouldOverflow)
{
    int32_t a0 = GAMMA2_ML_DSA_87 + 1;
    int32_t a1 = 1;

    int retVal = ML_DSA_87_MakeHint(a0, a1);

    EXPECT_EQ(retVal, RET_ERR);
}
