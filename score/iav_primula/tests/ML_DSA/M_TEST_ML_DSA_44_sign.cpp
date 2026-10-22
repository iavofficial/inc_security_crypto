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
#include "ML_DSA_44_sign.h"
}

/**********************************************************************************************************************/
/* DEFINES                                                                                                            */
/**********************************************************************************************************************/
#define RET_ERR 1

/**********************************************************************************************************************/
/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/
TEST(ML_DSA_44_sign_TEST, SignVerifyBadSignatureLength)
{

    uint8_t m[] = {"test_message"};
    uint32 mlen = sizeof(m);
    uint8_t pk[] = {"mock_key"};

    uint8_t sig[FSMSW_ML_DSA_44_CRYPTO_BYTES - 1] = {0};
    uint32 siglen = 1;

    int retVal = ML_DSA_44_Crypto_Sign_Verify(sig, siglen, m, mlen, pk);

    EXPECT_EQ(retVal, RET_ERR);
}

TEST(ML_DSA_44_sign_TEST, SignVerifyBadSignature)
{
    uint8_t sig[FSMSW_ML_DSA_44_CRYPTO_BYTES] = {0};
    uint32 siglen = FSMSW_ML_DSA_44_CRYPTO_BYTES;
    uint8_t m[] = {"test_message"};
    uint32 mlen = sizeof(m);
    uint8_t pk[] = {"mock_key"};

    int retVal = ML_DSA_44_Crypto_Sign_Verify(sig, siglen, m, mlen, pk);

    EXPECT_EQ(retVal, RET_ERR);
}

TEST(ML_DSA_44_sign_TEST, SignVerifyBadSignatureFormat)
{
    uint8_t sig[FSMSW_ML_DSA_44_CRYPTO_BYTES] = {0};
    uint32 siglen = FSMSW_ML_DSA_44_CRYPTO_BYTES;
    uint8_t m[] = {"test_message"};
    uint32 mlen = sizeof(m);
    uint8_t pk[] = {"mock_key"};

    int retVal = ML_DSA_44_Crypto_Sign_Verify(sig, siglen, m, mlen, pk);

    EXPECT_EQ(retVal, RET_ERR);
}

TEST(ML_DSA_44_sign_TEST, SignVerifyMessageNotSigned)
{
    uint8_t sig[FSMSW_ML_DSA_44_CRYPTO_BYTES];
    uint32 siglen;
    uint8_t m1[] = {"test_message_to_sign"};
    uint32 mlen1 = sizeof(m1);
    uint8_t m2[] = {"test_message_unsigned"};
    uint32 mlen2 = sizeof(m2);

    uint8_t pk[FSMSW_ML_DSA_44_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[FSMSW_ML_DSA_44_CRYPTO_SECRETKEYBYTES];

    ML_DSA_44_Crypto_Sign_KeyPair(pk, sk);
    ML_DSA_44_Crypto_Sign_Signature(sig, &siglen, m1, mlen1, sk);

    int retVal = ML_DSA_44_Crypto_Sign_Verify(sig, siglen, m2, mlen2, pk);

    EXPECT_EQ(retVal, RET_ERR);
}

TEST(ML_DSA_44_sign_TEST, SignOpenBadSigMsgSecretTooShort)
{
    uint8_t pk[] = {"mock_key"};
    uint8_t m[FSMSW_ML_DSA_44_CRYPTO_BYTES];
    uint32 mlen = FSMSW_ML_DSA_44_CRYPTO_BYTES;

    uint8_t sm[] = {"mock_secret"};
    uint32 smlen = sizeof(sm);

    int retVal = ML_DSA_44_Crypto_Sign_Open(m, &mlen, sm, smlen, pk);

    EXPECT_EQ(retVal, RET_ERR);
}

TEST(ML_DSA_44_sign_TEST, SignOpenBadSigMessageNotSigned)
{
    uint8_t pk[] = {"mock_key"};
    uint8_t m[FSMSW_ML_DSA_44_CRYPTO_BYTES];
    uint32 mlen = FSMSW_ML_DSA_44_CRYPTO_BYTES;

    uint8_t sm[2 * FSMSW_ML_DSA_44_CRYPTO_BYTES];
    uint32 smlen = sizeof(sm);

    FsmSw_CommonLib_RandomBytes(sm, smlen);

    int retVal = ML_DSA_44_Crypto_Sign_Open(m, &mlen, sm, smlen, pk);

    EXPECT_EQ(retVal, RET_ERR);
}
