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
#include "SLH_DSA_SHAKE_256sSimple_api.h"
#include "crc32.h"
}

/**********************************************************************************************************************/
/* DEFINES                                                                                                            */
/**********************************************************************************************************************/
#define TEST_SUCCESS ERR_OK

#define CRYPTO_PUBLICKEYBYTES SLH_DSA_SHAKE_256SSIMPLE_PK_BYTES
#define CRYPTO_SECRETKEYBYTES SLH_DSA_SHAKE_256SSIMPLE_SK_BYTES
#define CRYPTO_BYTES SLH_DSA_SHAKE_256SSIMPLE_BYTES
#define crypto_sign_keypair SLH_DSA_SHAKE_256sSimple_Crypto_Sign_KeyPair
#define crypto_sign_signature SLH_DSA_SHAKE_256sSimple_Crypto_Sign_Signature
#define crypto_sign_verify SLH_DSA_SHAKE_256sSimple_Crypto_Sign_Verify
#define crypto_sign SLH_DSA_SHAKE_256sSimple_Crypto_Sign
#define crypto_sign_open SLH_DSA_SHAKE_256sSimple_Crypto_Sign_Open

/**********************************************************************************************************************/
/* GLOBAL VARIABLES                                                                                                   */
/**********************************************************************************************************************/
sint8 retVal;

uint8 pk[CRYPTO_PUBLICKEYBYTES];
uint8 sk[CRYPTO_SECRETKEYBYTES];
uint8 sig[CRYPTO_BYTES];
uint32 siglen;
uint8 m[] = {"IAV quantumSAR"};
uint32 mlen = sizeof(m);
uint8 sm[CRYPTO_BYTES + sizeof(m)];
uint8 mout[sizeof(m)];
uint32 moutlen;
uint32 smlen;

uint32 crc32_pk;
uint32 crc32_sk;
uint32 crc32_sig;
uint32 crc32_sm;
uint32 crc32_mout;

uint32 crc32_pk_temp = 945567214;
uint32 crc32_sk_temp = 1868703703;
uint32 crc32_sig_temp = 3514675949;
uint32 crc32_sm_temp = 3148766263;
uint32 crc32_mout_temp = 2768244092;

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
 * Name:        SLH_DSA_SHAKE_256sSimple_TEST.CreatePkAndSk
 *
 * Description: Test should check the value of public and private key
 *
 ***********************************************************************************************************************/
TEST(SLH_DSA_SHAKE_256sSimple_TEST, CreatePkAndSk)
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
 * Name:        SLH_DSA_SHAKE_256sSimple_TEST.CreateSignature
 *
 * Description: Test should check the value of signature
 *
 ***********************************************************************************************************************/
TEST(SLH_DSA_SHAKE_256sSimple_TEST, CreateSignature)
{
    /*
     * Arguments:   - uint8  *sig:    pointer to output signature
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
 * Name:        SLH_DSA_SHAKE_256sSimple_TEST.VerifiesSignature
 *
 * Description: Test should check that the function SLH_DSA_SHAKE_256sSimple_Crypto_Sign_Verify returns 0
 *(signature has been verified correctly)
 *
 ***********************************************************************************************************************/
TEST(SLH_DSA_SHAKE_256sSimple_TEST, VerifiesSignature)
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
 * Name:        SLH_DSA_SHAKE_256sSimple_TEST.ComputSignedMessage
 *
 * Description: Test should check the value of computed signed message.
 *
 ***********************************************************************************************************************/
TEST(SLH_DSA_SHAKE_256sSimple_TEST, ComputSignedMessage)
{
    /*
     * Arguments:   -       uint8  *sm:    pointer to output signed message, can be equal to m
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
 * Name:        SLH_DSA_SHAKE_256sSimple_TEST.VerifySignedMessage
 *
 * Description: Test should verify the value of signed message.
 *
 ***********************************************************************************************************************/
TEST(SLH_DSA_SHAKE_256sSimple_TEST, VerifySignedMessage)
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