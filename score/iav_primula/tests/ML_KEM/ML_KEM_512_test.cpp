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
#include "ML_KEM_512_api.h"
#include "ML_KEM_api.h"
#include "crc32.h"
}

/**********************************************************************************************************************/
/* DEFINES                                                                                                            */
/**********************************************************************************************************************/
#define TEST_SUCCESS 0

#define CRYPTO_PUBLICKEYBYTES ML_KEM_512_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES ML_KEM_512_SECRETKEYBYTES
#define CRYPTO_INDCPA_BYTES ML_KEM_512_INDCPA_BYTES
#define CRYPTO_CIPHERTEXTBYTES ML_KEM_512_CIPHERTEXTBYTES
#define CRYPTO_INDCPA_MSGBYTES ML_KEM_512_INDCPA_MSGBYTES
#define CRYPTO_ML_KEM_SSBYTES ML_KEM_SSBYTES

/**********************************************************************************************************************/
/* GLOBAL VARIABLES                                                                                                   */
/**********************************************************************************************************************/
uint8 pk_alice[CRYPTO_PUBLICKEYBYTES];
uint8 sk_alice[CRYPTO_SECRETKEYBYTES];
uint8 ct[CRYPTO_CIPHERTEXTBYTES];
uint8 cypherMsg[CRYPTO_INDCPA_BYTES];
uint8 msg[CRYPTO_INDCPA_MSGBYTES];
uint8 outMsg[CRYPTO_INDCPA_MSGBYTES];

uint8 ss_alice[CRYPTO_ML_KEM_SSBYTES];
uint8 ss_bob[CRYPTO_ML_KEM_SSBYTES];
uint8 pk_bob[CRYPTO_PUBLICKEYBYTES];
uint8 sk_bob[CRYPTO_SECRETKEYBYTES];

uint32 crc32_sk_alice;
uint32 crc32_pk_alice;
uint32 crc32_sk_bob;
uint32 crc32_pk_bob;
uint32 crc32_ciphertext;
uint32 crc32_sharedsecret;
uint32 crc32_sharedsecret_bob;
uint32 crc32_cypherMsg;
uint32 crc32_outMsg;

int retVal;

uint32 crc32_pk_alice_temp = 0x5454bb0c;
uint32 crc32_sk_alice_temp = 0x01466113;
uint32 crc32_pk_bob_temp = 0x15abf1ed;
uint32 crc32_sk_bob_temp = 0xe94ff71e;
uint32 crc32_ciphertext_temp = 0x569DE125;
uint32 crc32_sharedsecret_temp = 0xCA681B2D;
uint32 crc32_cypherMsg_temp = 0x2f2bc6d4;
uint32 crc32_outMsg_temp = 0x021d9304;

/**********************************************************************************************************************/
/* HELP FUNCTIONS                                                                                                     */
/**********************************************************************************************************************/

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
 * Name:        ML_KEM_512_TEST.CreatePkAndSkAlice
 *
 * Description: Test should check the value of public and private key of alice
 *
 ***********************************************************************************************************************/
TEST(ML_KEM_512_TEST, CreatePkAndSkAlice)
{
    /*
     * Arguments:   - uint8 *pk_alice: pointer to output public key of alice  (of length CRYPTO_PUBLICKEYBYTES bytes)
     *              - uint8 *sk_alice: pointer to output private key of alice (of length CRYPTO_SECRETKEYBYTES bytes)
     */
    ML_KEM_512_Crypto_Kem_KeyPair(pk_alice, sk_alice);
    crc32_pk_alice = crc32(pk_alice, CRYPTO_PUBLICKEYBYTES);
    crc32_sk_alice = crc32(sk_alice, CRYPTO_SECRETKEYBYTES);

    EXPECT_EQ(crc32_pk_alice, crc32_pk_alice_temp);
    EXPECT_EQ(crc32_sk_alice, crc32_sk_alice_temp);
}

/***********************************************************************************************************************
 * Name:        ML_KEM_512_TEST.CreatePkAndSkBob
 *
 * Description: Test should check the value of public and private key of bob
 *
 ***********************************************************************************************************************/
TEST(ML_KEM_512_TEST, CreatePkAndSkBob)
{
    /*
     * Arguments:   - uint8 *pk_alice: pointer to output public key of bob  (of length CRYPTO_PUBLICKEYBYTES bytes)
     *              - uint8 *sk_alice: pointer to output private key of bob (of length CRYPTO_SECRETKEYBYTES bytes)
     */
    ML_KEM_512_Crypto_Kem_KeyPair(pk_bob, sk_bob);

    crc32_pk_bob = crc32(pk_bob, CRYPTO_PUBLICKEYBYTES);
    crc32_sk_bob = crc32(sk_bob, CRYPTO_SECRETKEYBYTES);

    EXPECT_EQ(crc32_pk_bob, crc32_pk_bob_temp);
    EXPECT_EQ(crc32_sk_bob, crc32_sk_bob_temp);
}

/***********************************************************************************************************************
 * Name:        ML_KEM_512_TEST.GenCipherTxtAndSharedSecretAlice
 *
 * Description: Test should check the value of the cipher text and the shared secret of alice.
 *
 ***********************************************************************************************************************/
TEST(ML_KEM_512_TEST, GenCipherTxtAndSharedSecretAlice)
{
    /*
     * Arguments:   -       uint8 *ct:       pointer to output cipher text (of length CRYPTO_CIPHERTEXTBYTES bytes)
     *              -       uint8 *ss_alice: pointer to output shared secret (of length CRYPTO_ML_KEM_SSBYTES bytes)
     *              - const uint8 *pk_bob:   pointer to input public key (of length CRYPTO_PUBLICKEYBYTES bytes)
     */
    ML_KEM_512_Crypto_Kem_Enc(ct, ss_alice, pk_bob);

    crc32_ciphertext = crc32(ct, CRYPTO_CIPHERTEXTBYTES);
    crc32_sharedsecret = crc32(ss_alice, CRYPTO_ML_KEM_SSBYTES);

    EXPECT_EQ(crc32_ciphertext, crc32_ciphertext_temp);
    EXPECT_EQ(crc32_sharedsecret, crc32_sharedsecret_temp);
}

/***********************************************************************************************************************
 * Name:        ML_KEM_512_TEST.GenSharedSecretForCipherTxtAndPrivateKeyBob
 *
 * Description: Test should check the decription of the shared secret from bob and the default shared secret.
 *
 ***********************************************************************************************************************/
TEST(ML_KEM_512_TEST, GenSharedSecretForCipherTxtAndPrivateKeyBob)
{
    /*
     * Arguments:   -       uint8 *ss_bob: pointer to output shared secret (of length CRYPTO_ML_KEM_SSBYTES bytes)
     *              - const uint8 *ct:     pointer to input cipher text (of length CRYPTO_CIPHERTEXTBYTES bytes)
     *              - const uint8 *sk_bob: pointer to input private key (of length CRYPTO_SECRETKEYBYTES bytes)
     */
    ML_KEM_512_Crypto_Kem_Dec(ss_bob, ct, sk_bob);

    crc32_sharedsecret_bob = crc32(ss_bob, CRYPTO_ML_KEM_SSBYTES);

    EXPECT_EQ(crc32_sharedsecret_bob, crc32_sharedsecret_temp);
}
