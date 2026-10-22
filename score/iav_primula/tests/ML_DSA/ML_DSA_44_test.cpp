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
#include "ML_DSA_44_api.h"
#include "crc32.h"
}

/**********************************************************************************************************************/
/* DEFINES                                                                                                            */
/**********************************************************************************************************************/
#define TEST_SUCCESS ERR_OK

#define CRYPTO_PUBLICKEYBYTES FSMSW_ML_DSA_44_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES FSMSW_ML_DSA_44_CRYPTO_SECRETKEYBYTES
#define CRYPTO_BYTES FSMSW_ML_DSA_44_CRYPTO_BYTES
#define crypto_sign_keypair ML_DSA_44_Crypto_Sign_KeyPair
#define crypto_sign_signature ML_DSA_44_Crypto_Sign_Signature
#define crypto_sign_verify ML_DSA_44_Crypto_Sign_Verify
#define crypto_sign ML_DSA_44_Crypto_Sign
#define crypto_sign_open ML_DSA_44_Crypto_Sign_Open

/**********************************************************************************************************************/
/* MODULE GLOBAL VARIABLES */
/**********************************************************************************************************************/
static uint8 retVal;

static uint8 pk[CRYPTO_PUBLICKEYBYTES];
static uint8 sk[CRYPTO_SECRETKEYBYTES];
static uint8 sig[CRYPTO_BYTES];
static uint32 siglen;
static uint8 m[] = {"IAV quantumSAR"};
static uint32 mlen = sizeof(m);
static uint8 sm[CRYPTO_BYTES + sizeof(m)];
static uint8 mout[sizeof(m)];
static uint32 moutlen;
static uint32 smlen;

static uint32 crc32_pk;
static uint32 crc32_sk;
static uint32 crc32_sig;
static uint32 crc32_sm;
static uint32 crc32_mout;

static uint32 crc32_pk_temp = 0xce08cc72;
static uint32 crc32_sk_temp = 0xb4435aec;
static uint32 crc32_sig_temp = 0x690399c8;
static uint32 crc32_sm_temp = 0xad535ca4;
static uint32 crc32_mout_temp = 0xa5000d7c;

/**********************************************************************************************************************/
/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/

/*
 * Info: - As these are smoke tests, a single test for the required process would be very confusing. It was therefore
 *         decided to write small individual test cases in a test suite, which can depend on each other.
 *       - Function crc32() is used to generate a crc32 signature for various arrays. The temporary signature is used in
 *         the individual tests as a reference value for the signature of the source code arrays.
 */

/***********************************************************************************************************************
 * Name:        ML_DSA_44_TEST.CreatePkAndSk
 *
 * Description: Test should check the value of public and private key
 *
 ***********************************************************************************************************************/
TEST(ML_DSA_44_TEST, CreatePkAndSk)
{
    /*
     * Arguments:   - uint8 *pk: pointer to output public key
     *              - uint8 *sk: pointer to output private key
     */
    crypto_sign_keypair(pk, sk);
    crc32_pk = crc32(pk, CRYPTO_PUBLICKEYBYTES);
    crc32_sk = crc32(sk, CRYPTO_SECRETKEYBYTES);

    EXPECT_EQ(crc32_pk, crc32_pk_temp);
    EXPECT_EQ(crc32_sk, crc32_sk_temp);
}

/***********************************************************************************************************************
 * Name:        ML_DSA_44_TEST.CreateSignature
 *
 * Description: Test should check the value of signature
 *
 ***********************************************************************************************************************/
TEST(ML_DSA_44_TEST, CreateSignature)
{
    /*
     * Arguments:   - uint8  *sig:    pointer to output signature (of length FSMSW_ML_DSA_44_CRYPTO_BYTES)
     *              - uint32 *siglen: pointer to output length of signature
     *              - uint8  *m:      pointer to message to be signed
     *              - uint32  mlen:   length of message
     *              - uint8  *sk:     pointer to bit-packed secret key
     */
    crypto_sign_signature(sig, &siglen, m, mlen, sk);
    crc32_sig = crc32(sig, siglen);

    EXPECT_EQ(crc32_sig, crc32_sig_temp);
}

/***********************************************************************************************************************
 * Name:        ML_DSA_44_TEST.VerifiesSignature
 *
 * Description: Test should check that the function ML_DSA_44_Crypto_Sign_Verify returns 0 (signature has been
 *              verified correctly)
 *
 ***********************************************************************************************************************/
TEST(ML_DSA_44_TEST, VerifiesSignature)
{
    /*
     * Arguments:   -       uint8  *m:      pointer to input signature
     *              -       uint32  siglen: length of signature
     *              - const uint8  *m:      pointer to message
     *              -       uint32  mlen:   length of message
     *              - const uint8  *pk:     pointer to bit-packed public key
     */
    retVal = crypto_sign_verify(sig, siglen, m, mlen, pk);

    EXPECT_EQ(retVal, TEST_SUCCESS);
}

/***********************************************************************************************************************
 * Name:        ML_DSA_44_TEST.ComputSignedMessage
 *
 * Description: Test should check the value of computed signed message.
 *
 ***********************************************************************************************************************/
TEST(ML_DSA_44_TEST, ComputSignedMessage)
{
    /*
     * Arguments:   -       uint8  *sm:    pointer to output signed message (allocated
     *                                     array with FSMSW_ML_DSA_44_CRYPTO_BYTES + mlen bytes), can be equal to m
     *              -       uint32 *smlen: pointer to output length of signed message
     *              - const uint8  *m:     pointer to message to be signed
     *              -       uint32  mlen:  length of message
     *              - const uint8  *sk:    pointer to bit-packed secret key
     */
    crypto_sign(sm, &smlen, m, mlen, sk);
    crc32_sm = crc32(sm, smlen);

    EXPECT_EQ(crc32_sm, crc32_sm_temp);
}

/***********************************************************************************************************************
 * Name:        ML_DSA_44_TEST.VerifySignedMessage
 *
 * Description: Test should verify the value of signed message.
 *
 ***********************************************************************************************************************/
TEST(ML_DSA_44_TEST, VerifySignedMessage)
{
    /*
     * Arguments:   -       uint8  *mout:    pointer to output message (allocated array with smlen bytes), can be equal
     * to sm
     *              -       uint32 *moutlen: pointer to output length of message
     *              - const uint8  *sm:      pointer to signed message
     *              -       uint32  smlen:   length of signed message
     *              - const uint8  *pk:      pointer to bit-packed public key
     */
    retVal = crypto_sign_open(mout, &moutlen, sm, smlen, pk);
    crc32_mout = crc32(mout, moutlen);

    EXPECT_EQ(retVal, TEST_SUCCESS);
    EXPECT_EQ(crc32_mout, crc32_mout_temp);
}