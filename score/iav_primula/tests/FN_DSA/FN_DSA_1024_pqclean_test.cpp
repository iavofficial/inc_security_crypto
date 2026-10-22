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
#include "FN_DSA_1024_api.h"
#include "FsmSw_CommonLib.h"
}
/**********************************************************************************************************************/
/* DEFINES                                                                                                            */
/**********************************************************************************************************************/
#define FN_DSA_1024_NONCELEN 40u

/**********************************************************************************************************************/
/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/

/* FN_DSA_1024_Crypto_Sign_Signature */
TEST(PQClean_FN_DSA_1024_pqclean_TEST, CryptoSignSignatureDoSignReturnsMinusOne)
{
    uint32 mlen;
    uint32 siglen = 0U;
    uint8_t sig[FN_DSA_1024_CRYPTO_BYTES];
    uint8_t m[] = {"test message"};
    mlen = sizeof(m);

    uint8_t pk[FN_DSA_1024_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[FN_DSA_1024_CRYPTO_SECRETKEYBYTES];
    FN_DSA_1024_Crypto_Sign_KeyPair(pk, sk);
    sk[0] = 0x50 + 9;  // ensure sk[0] != 0x50 + 10

    int retVal = FN_DSA_1024_Crypto_Sign_Signature(sig, &siglen, m, mlen, sk);
    EXPECT_EQ(retVal, ERR_NOT_OK);
}

/* FN_DSA_1024_Crypto_Sign_Verify */
TEST(PQClean_FN_DSA_1024_pqclean_TEST, CryptoSignVerifySiglenLessThanOnePlusNoncelen)
{
    uint32 mlen;
    uint32 siglen = 0;  // ensure siglen < 1 + FN_DSA_1024_NONCELEN
    uint8_t sig[FN_DSA_1024_CRYPTO_BYTES];
    uint8_t m[] = {"test message"};
    mlen = sizeof(m);

    uint8_t pk[FN_DSA_1024_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[FN_DSA_1024_CRYPTO_SECRETKEYBYTES];
    FN_DSA_1024_Crypto_Sign_KeyPair(pk, sk);

    int retVal = FN_DSA_1024_Crypto_Sign_Verify(sig, siglen, m, mlen, pk);
    EXPECT_EQ(retVal, ERR_NOT_OK);
}

/* FN_DSA_1024_Crypto_Sign_Verify */
TEST(PQClean_FN_DSA_1024_pqclean_TEST, CryptoSignVerifySigZeroNotEqExpectedValue)
{
    uint32 mlen;
    uint32 siglen = FN_DSA_1024_CRYPTO_BYTES;
    uint8_t sig[FN_DSA_1024_CRYPTO_BYTES];
    uint8_t m[] = {"test message"};
    mlen = sizeof(m);

    uint8_t pk[FN_DSA_1024_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[FN_DSA_1024_CRYPTO_SECRETKEYBYTES];
    FN_DSA_1024_Crypto_Sign_KeyPair(pk, sk);
    FN_DSA_1024_Crypto_Sign_Signature(sig, &siglen, m, mlen, sk);
    sig[0] = 0x30 + 9;  // ensure sig[0] != 0x30 + 10

    int retVal = FN_DSA_1024_Crypto_Sign_Verify(sig, siglen, m, mlen, pk);
    EXPECT_EQ(retVal, ERR_NOT_OK);
}

/* FN_DSA_1024_Crypto_Sign_Verify */
TEST(PQClean_FN_DSA_1024_pqclean_TEST, CryptoSignVerifyDoVerifyReturnsNegativeValue)
{
    uint32 mlen;
    uint32 siglen = FN_DSA_1024_CRYPTO_BYTES;
    uint8_t sig[FN_DSA_1024_CRYPTO_BYTES];
    uint8_t m[] = {"test message"};
    mlen = sizeof(m);

    uint8_t pk[FN_DSA_1024_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[FN_DSA_1024_CRYPTO_SECRETKEYBYTES];
    FN_DSA_1024_Crypto_Sign_KeyPair(pk, sk);
    FN_DSA_1024_Crypto_Sign_Signature(sig, &siglen, m, mlen, sk);
    pk[0] = 0x00 + 9;  // ensure pk[0] != 0x00 + 10

    int retVal = FN_DSA_1024_Crypto_Sign_Verify(sig, siglen, m, mlen, pk);
    EXPECT_EQ(retVal, ERR_NOT_OK);
}

/* FN_DSA_1024_Crypto_Sign */
TEST(PQClean_FN_DSA_1024_pqclean_TEST, CryptoSignSkZeroNotEqExpectedValue)
{
    uint32 mlen;
    uint32 smlen = 0U;
    uint8_t m[] = {"test message"};
    mlen = sizeof(m);
    uint8_t sm[2 + FN_DSA_1024_NONCELEN + sizeof(m)];

    uint8_t pk[FN_DSA_1024_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[FN_DSA_1024_CRYPTO_SECRETKEYBYTES];
    FN_DSA_1024_Crypto_Sign_KeyPair(pk, sk);
    sk[0] = 0x50 + 9;  // ensure sk[0] !=  0x50 + 10

    int retVal = FN_DSA_1024_Crypto_Sign(sm, &smlen, m, mlen, sk);
    EXPECT_EQ(retVal, ERR_NOT_OK);
}

/* FN_DSA_1024_Crypto_Sign_Open */
TEST(PQClean_FN_DSA_1024_pqclean_TEST, CryptoSignOpenSmlenLessThan3PlusNoncelen)
{
    uint32 smlen = 0;  // ensure smlen < 3 + FN_DSA_1024_NONCELEN
    uint32 mlen;
    uint8_t m[] = {"test message"};
    mlen = sizeof(m);
    uint8_t sm[2 + FN_DSA_1024_NONCELEN + sizeof(m)];

    uint8_t pk[FN_DSA_1024_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[FN_DSA_1024_CRYPTO_SECRETKEYBYTES];
    FN_DSA_1024_Crypto_Sign_KeyPair(pk, sk);

    int retVal = FN_DSA_1024_Crypto_Sign_Open(m, &mlen, sm, smlen, pk);
    EXPECT_EQ(retVal, ERR_NOT_OK);
}

/* FN_DSA_1024_Crypto_Sign_Open */
TEST(PQClean_FN_DSA_1024_pqclean_TEST, CryptoSignOpenSigbuflenNotEqExpectedValue)
{

    uint8_t pk[FN_DSA_1024_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[FN_DSA_1024_CRYPTO_SECRETKEYBYTES];
    FN_DSA_1024_Crypto_Sign_KeyPair(pk, sk);

    uint32 smlen;
    uint32 mlen;
    uint8_t m[] = {"PQClean test message"};
    mlen = sizeof(m);  // 21
    uint8_t sm[FN_DSA_1024_CRYPTO_BYTES + sizeof(m)];
    smlen = sizeof(sm);

    FN_DSA_1024_Crypto_Sign(sm, &smlen, m, mlen, sk);
    sm[0] = 0x0;
    sm[1] = 0x0;  // sigbuflen should be lt 2 and return negative value

    int retVal = FN_DSA_1024_Crypto_Sign_Open(m, &mlen, sm, smlen, pk);
    EXPECT_EQ(retVal, ERR_NOT_OK);
}

/* FN_DSA_1024_Crypto_Sign_Open */
TEST(PQClean_FN_DSA_1024_pqclean_TEST, CryptoSignOpenSmXNotEqExpectedValue)
{

    uint8_t pk[FN_DSA_1024_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[FN_DSA_1024_CRYPTO_SECRETKEYBYTES];
    FN_DSA_1024_Crypto_Sign_KeyPair(pk, sk);

    uint32 smlen;
    uint32 mlen;
    uint32 sigbuflen, pmlen;
    uint8_t m[] = {"PQClean test message"};
    mlen = sizeof(m);  // 21
    uint8_t sm[FN_DSA_1024_CRYPTO_BYTES + sizeof(m)];
    smlen = sizeof(sm);

    FN_DSA_1024_Crypto_Sign(sm, &smlen, m, mlen, sk);
    sigbuflen = (((uint32)sm[0] << 8) | (uint32)sm[1]) - 1;
    pmlen = smlen - FN_DSA_1024_NONCELEN - 3 - sigbuflen;
    sm[2 + FN_DSA_1024_NONCELEN + pmlen] = 0x20 + 9;  // ensure sm[2 + FN_DSA_1024_NONCELEN + pmlen] != 0x20 + 10;

    int retVal = FN_DSA_1024_Crypto_Sign_Open(m, &mlen, sm, smlen, pk);
    EXPECT_EQ(retVal, ERR_NOT_OK);
}

/* FN_DSA_1024_Crypto_Sign_Open */
TEST(PQClean_FN_DSA_1024_pqclean_TEST, CryptoSignOpenDoVerifyLessThanZero)
{
    uint8_t pk[FN_DSA_1024_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[FN_DSA_1024_CRYPTO_SECRETKEYBYTES];
    FN_DSA_1024_Crypto_Sign_KeyPair(pk, sk);

    uint32 smlen;
    uint32 mlen;
    uint32 sigbuflen, pmlen;
    uint8_t m[] = {"PQClean test message"};
    mlen = sizeof(m);  // 21
    uint8_t sm[FN_DSA_1024_CRYPTO_BYTES + sizeof(m)];
    smlen = sizeof(sm);

    FN_DSA_1024_Crypto_Sign(sm, &smlen, m, mlen, sk);
    pk[0] = 0x00 + 9;  // ensure pk[0] != 0x00 + 10

    int retVal = FN_DSA_1024_Crypto_Sign_Open(m, &mlen, sm, smlen, pk);
    EXPECT_EQ(retVal, ERR_NOT_OK);
}
