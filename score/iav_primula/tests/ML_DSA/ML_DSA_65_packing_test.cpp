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
#include "ML_DSA_65_packing.h"
#include "ML_DSA_65_sign.h"
}

/**********************************************************************************************************************/
/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/
TEST(ML_DSA_65_packing_TEST, UnpackSigMalformedBadOrder)
{
    uint8_t bad_sig[FSMSW_ML_DSA_65_CRYPTO_BYTES];
    for (int i = 0; i < FSMSW_ML_DSA_65_CRYPTO_BYTES; ++i)
    {
        bad_sig[i] = FSMSW_ML_DSA_65_CRYPTO_BYTES - (i % 256);
    }

    uint8_t c[CTILDEBYTES_ML_DSA_65];
    polyvecl_D3 z;
    polyveck_D3 h;

    int retVal = ML_DSA_65_UnpackSig(c, &z, &h, bad_sig);

    EXPECT_EQ(retVal, 1);
}

TEST(ML_DSA_65_packing_TEST, UnpackSigMalformedCoeffOutOfRange)
{
    uint8_t bad_sig[FSMSW_ML_DSA_65_CRYPTO_BYTES];
    for (int i = 0; i < FSMSW_ML_DSA_65_CRYPTO_BYTES; ++i)
    {
        bad_sig[i] = i & 0xffff;
    }

    uint8_t c[CTILDEBYTES_ML_DSA_65];
    polyvecl_D3 z;
    polyveck_D3 h;

    int retVal = ML_DSA_65_UnpackSig(c, &z, &h, bad_sig);

    EXPECT_EQ(retVal, 1);
}

TEST(ML_DSA_65_packing_TEST, UnpackSigMalformedPadding)
{
    uint8_t bad_sig[FSMSW_ML_DSA_65_CRYPTO_BYTES];

    uint8_t c[CTILDEBYTES_ML_DSA_65];
    polyvecl_D3 z;
    polyveck_D3 h;

    uint8_t sig[FSMSW_ML_DSA_65_CRYPTO_BYTES];
    uint32 siglen;

    uint8_t m[] = {"IAV quantumSAR"};
    uint32_t mlen = sizeof(m);

    uint8_t pk[FSMSW_ML_DSA_65_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[FSMSW_ML_DSA_65_CRYPTO_SECRETKEYBYTES];

    ML_DSA_65_Crypto_Sign_KeyPair(pk, sk);
    ML_DSA_65_Crypto_Sign_Signature(sig, &siglen, m, mlen, sk);

    for (int i = 0; i < FSMSW_ML_DSA_65_CRYPTO_BYTES; ++i)
    {
        sig[siglen - 1] = sig[siglen - 2] + 1;
    }

    int retVal = ML_DSA_65_UnpackSig(c, &z, &h, sig);

    EXPECT_EQ(retVal, 1);
}