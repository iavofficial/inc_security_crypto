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
#include "SLH_DSA_SHA2_256fSimple_params.h"
#include "SLH_DSA_SHA2_256fSimple_sign.h"
}

/**********************************************************************************************************************/
/* DEFINES                                                                                                            */
/**********************************************************************************************************************/
#define RET_ERR 1
#define CRYPTO_PUBLICKEYBYTES SLH_DSA_SHA2_256FSIMPLE_PK_BYTES
#define CRYPTO_SECRETKEYBYTES SLH_DSA_SHA2_256FSIMPLE_SK_BYTES
#define CRYPTO_BYTES SLH_DSA_SHA2_256FSIMPLE_BYTES
#define crypto_sign_keypair SLH_DSA_SHA2_256fSimple_Crypto_Sign_KeyPair
#define crypto_sign_signature SLH_DSA_SHA2_256fSimple_Crypto_Sign_Signature
#define crypto_sign_verify SLH_DSA_SHA2_256fSimple_Crypto_Sign_Verify
#define crypto_sign SLH_DSA_SHA2_256fSimple_Crypto_Sign
#define crypto_sign_open SLH_DSA_SHA2_256fSimple_Crypto_Sign_Open

/**********************************************************************************************************************/
/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/
TEST(SLH_DSA_SHA2_256fSimple_sign_TEST, SignVerifyWrongSignatureLen)
{
    uint8_t sig[CRYPTO_BYTES];
    uint32 siglen;
    uint8_t m[] = {"test_message_to_sign"};
    uint32 mlen = sizeof(m);
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    crypto_sign_keypair(pk, sk);
    crypto_sign_signature(sig, &siglen, m, mlen, sk);
    const int bad_siglen = CRYPTO_BYTES - 1;

    int retVal = crypto_sign_verify(sig, bad_siglen, m, mlen, pk);

    EXPECT_EQ(retVal, RET_ERR);
}

TEST(SLH_DSA_SHA2_256fSimple_sign_TEST, SignVerifyMalformedPublicRoot)
{
    uint8_t sig[CRYPTO_BYTES];
    uint32 siglen;
    uint8_t m[] = {"test_message_to_sign"};
    uint32 mlen = sizeof(m);
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    crypto_sign_keypair(pk, sk);
    crypto_sign_signature(sig, &siglen, m, mlen, sk);

    // Change value with XOR
    pk[CRYPTO_PUBLICKEYBYTES - 1] ^= 0xff;

    int retVal = crypto_sign_verify(sig, siglen, m, mlen, pk);

    EXPECT_EQ(retVal, RET_ERR);
}

TEST(SLH_DSA_SHA2_256fSimple_sign_TEST, SignOpenBadSigMsgSecretTooShort)
{
    uint8_t m[] = {"mock_message"};
    uint32 mlen = sizeof(m);
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    crypto_sign_keypair(pk, sk);

    uint8_t sm[] = {"mock_secret"};
    uint32 smlen = sizeof(sm);

    int retVal = crypto_sign_open(m, &mlen, sm, smlen, pk);

    EXPECT_EQ(retVal, RET_ERR);
}

TEST(SLH_DSA_SHA2_256fSimple_sign_TEST, SignOpenBadSigMessageNotSigned)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {"mock_key"};
    uint8_t m[2 * CRYPTO_BYTES];
    uint32 mlen = sizeof(m);

    uint8_t sm[2 * CRYPTO_BYTES];
    uint32 smlen = sizeof(sm);

    FsmSw_CommonLib_RandomBytes(sm, smlen);

    int retVal = crypto_sign_open(m, &mlen, sm, smlen, pk);

    EXPECT_EQ(retVal, RET_ERR);
}
