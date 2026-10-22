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
#include "ML_KEM_encapDecapFIPS203Tr1_testData.h"
#include "ML_KEM_encapDecapFIPS203_testData.h"
#include "ML_KEM_keyGenFIPS203_testData.h"
#include "module_test_support.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

extern "C" {
#include "FsmSw_CommonLib.h"
#include "ML_KEM_512_api.h"
#include "ML_KEM_params.h"
#include "crc32.h"
}

/**********************************************************************************************************************/
/* DEFINES                                                                                                            */
/**********************************************************************************************************************/
#define CRYPTO_PUBLICKEYBYTES ML_KEM_512_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES ML_KEM_512_SECRETKEYBYTES
#define CRYPTO_INDCPA_BYTES ML_KEM_512_INDCPA_BYTES
#define CRYPTO_CIPHERTEXTBYTES ML_KEM_512_CIPHERTEXTBYTES
#define CRYPTO_INDCPA_MSGBYTES ML_KEM_512_INDCPA_MSGBYTES
#define CRYPTO_ML_KEM_SSBYTES ML_KEM_SSBYTES
#define CRYPTO_ML_KEM_OFFSET_PK CRYPTO_INDCPA_BYTES
/**********************************************************************************************************************/
/* GLOBAL VARIABLES                                                                                                   */
/**********************************************************************************************************************/
static uint8 pk_alice[CRYPTO_PUBLICKEYBYTES];
static uint8 sk_alice[CRYPTO_SECRETKEYBYTES];
static uint8 ct[CRYPTO_CIPHERTEXTBYTES];
static uint8 cypherMsg[CRYPTO_INDCPA_BYTES];
static uint8 msg[CRYPTO_INDCPA_MSGBYTES];
static uint8 outMsg[CRYPTO_INDCPA_MSGBYTES];

static uint8 ss_alice[CRYPTO_ML_KEM_SSBYTES];
static uint8 ss_bob[CRYPTO_ML_KEM_SSBYTES];
static uint8 pk_bob[CRYPTO_PUBLICKEYBYTES];
static uint8 sk_bob[CRYPTO_SECRETKEYBYTES];

static uint32 crc32_sk_alice;
static uint32 crc32_pk_alice;
static uint32 crc32_sk_bob;
static uint32 crc32_pk_bob;
static uint32 crc32_ciphertext;
static uint32 crc32_sharedsecret_alice;
static uint32 crc32_sharedsecret_bob;
static uint32 crc32_cypherMsg;
static uint32 crc32_outMsg;

static int retVal;

static uint32 crc32_pk_alice_temp;
static uint32 crc32_sk_alice_temp;
static uint32 crc32_pk_bob_temp;
static uint32 crc32_sk_bob_temp;
static uint32 crc32_ciphertext_temp;
static uint32 crc32_sharedsecret_temp;
static uint32 crc32_cypherMsg_temp;
static uint32 crc32_outMsg_temp;

/**********************************************************************************************************************/
/* HELP FUNCTIONS                                                                                                     */
/**********************************************************************************************************************/
extern "C" {
void ML_KEM_512_Indcpa_Dec(uint8 m[ML_KEM_512_INDCPA_MSGBYTES],
                           const uint8 c[ML_KEM_512_INDCPA_BYTES],
                           const uint8 sk[CRYPTO_SECRETKEYBYTES]);
void ML_KEM_512_Indcpa_Enc(uint8 c[ML_KEM_512_INDCPA_BYTES],
                           const uint8 m[ML_KEM_512_INDCPA_MSGBYTES],
                           const uint8 pk[CRYPTO_PUBLICKEYBYTES],
                           const uint8 coins[ML_KEM_SYMBYTES]);
void ML_KEM_512_Indcpa_KeyPair(uint8 pk[CRYPTO_PUBLICKEYBYTES], uint8 sk[CRYPTO_SECRETKEYBYTES]);
void FsmSw_Fips202_Sha3_512(uint8* const output, const uint8* const input, uint32 inlen);
void FsmSw_Fips202_Sha3_256(uint8* const output, const uint8* const input, uint32 inlen);
}

/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/

/*
 * Info: - As these are smoke tests, a single test for the required process would be very confusing. It was therefore
 *         decided to write small individual test cases in a test suite, which can depend on each other.
 *       - Function crc32() is used to generate a crc32 signature for various arrays. The temporary signature is used in
 *         the individual tests as a reference value for the signature of the source code arrays.
 */

/***********************************************************************************************************************
 * Name:        ML_KEM_512_Legacy_TEST.CreatePkAndSkAlice
 *
 * Description: Test should check the value of public and private key of alice
 *
 **********************************************************************************************************************/
TEST(ML_KEM_512_Legacy_TEST, CreatePkAndSkAlice)
{
    /*
     * Arguments:   - uint8 *pk_alice: pointer to output public key of alice  (of length CRYPTO_PUBLICKEYBYTES bytes)
     *              - uint8 *sk_alice: pointer to output private key of alice (of length CRYPTO_SECRETKEYBYTES bytes)
     */

    for (auto& testGroup : ML_KEM_keyGen_testGroups)
    {
        // check for ML-KEM-512 test group and only testgroups with function = decapsulation
        if (("ML-KEM-512" == testGroup.parameterSet))
        {
            for (auto& curTest : testGroup.tests)
            {
                // get randomness d text from NIST testvectors
                std::size_t len = 0;
                uint8_t* randD = hexStringToUint8Array(curTest.d, len);
                ASSERT_NE(randD, nullptr);
                ASSERT_EQ(len, ML_KEM_SYMBYTES);

                // get randomness z text from NIST testvectors
                std::size_t lenZ = 0;
                uint8_t* randZ = hexStringToUint8Array(curTest.z, lenZ);
                ASSERT_NE(randZ, nullptr);
                ASSERT_EQ(lenZ, ML_KEM_SYMBYTES);

                // build byte array for decapsulation key (sk_alice)
                std::size_t dkLen = 0;
                uint8_t* dkNist = hexStringToUint8Array(curTest.dk, dkLen);
                ASSERT_NE(dkNist, nullptr);
                ASSERT_EQ(dkLen, CRYPTO_SECRETKEYBYTES);
                crc32_sk_alice_temp = crc32(dkNist, CRYPTO_SECRETKEYBYTES);

                // build byte array for encapsulation key (pk_pob)
                std::size_t ekLen = 0;
                uint8_t* ekNist = hexStringToUint8Array(curTest.ek, ekLen);
                ASSERT_NE(ekNist, nullptr);
                ASSERT_EQ(ekLen, CRYPTO_PUBLICKEYBYTES);
                crc32_pk_alice_temp = crc32(ekNist, CRYPTO_PUBLICKEYBYTES);

                // ML_KEM_512_Crypto_Kem_KeyPair(pk_alice, sk_alice); //does not work directly, because 2x randomness
                // (d,z) neededd
                //  So split it into internal KeyGen with randomness d set to Nist test d

                // provide deterministic seed via the test RNG override
                {
                    ModuleTestRngOverride rng(randD, ML_KEM_SYMBYTES);
                    ML_KEM_512_Indcpa_KeyPair(pk_alice, sk_alice);
                }
                crc32_pk_alice = crc32(pk_alice, CRYPTO_PUBLICKEYBYTES);
                crc32_sk_alice = crc32(sk_alice, CRYPTO_SECRETKEYBYTES);
                EXPECT_EQ(crc32_pk_alice,
                          crc32_pk_alice_temp);  // test should not fail, due to ek is final after this step
                EXPECT_NE(crc32_sk_alice, crc32_sk_alice_temp);  // test should fail, due to dk is an intermediate value

                // and then afterward copy the remaining steps from ML_KEM_512_Crypto_Kem_KeyPair with newly set
                // randomness z
                for (uint16 i = 0; i < CRYPTO_PUBLICKEYBYTES; i++)
                {
                    sk_alice[i + CRYPTO_ML_KEM_OFFSET_PK] = pk_alice[i];
                }

                FsmSw_Fips202_Sha3_256(
                    &sk_alice[CRYPTO_SECRETKEYBYTES - (2u * ML_KEM_SYMBYTES)], pk_alice, ML_KEM_512_PUBLICKEYBYTES);

                // provide deterministic seed via the test RNG override
                {
                    ModuleTestRngOverride rng(randZ, ML_KEM_SYMBYTES);
                    /* Value z for pseudo-random output on reject */
                    (void)FsmSw_CommonLib_RandomBytes(&sk_alice[CRYPTO_SECRETKEYBYTES - ML_KEM_SYMBYTES],
                                                      ML_KEM_SYMBYTES);
                }
                crc32_sk_alice = crc32(sk_alice, CRYPTO_SECRETKEYBYTES);

                EXPECT_EQ(crc32_sk_alice, crc32_sk_alice_temp);

                // clean up dyn. memory allocs
                delete[] ekNist;
                ekNist = nullptr;
                delete[] dkNist;
                dkNist = nullptr;
                delete[] randD;
                randD = nullptr;
                delete[] randZ;
                randZ = nullptr;
            }
        }
    }
}

/***********************************************************************************************************************
 * Name:        ML_KEM_512_Legacy_TEST.GenCipherTxtAndSharedSecretAlice
 *
 * Description: Test should check the value of the cipher text and the shared secret of alice.
 *
 **********************************************************************************************************************/
TEST(ML_KEM_512_Legacy_TEST, GenCipherTxtAndSharedSecretAlice)
{
    /*
     * Arguments:   -       uint8 *ct:       pointer to output cipher text (of length CRYPTO_CIPHERTEXTBYTES bytes)
     *              -       uint8 *ss_alice: pointer to output shared secret (of length CRYPTO_ML_KEM_SSBYTES bytes)
     *              - const uint8 *pk_bob:   pointer to input public key (of length CRYPTO_PUBLICKEYBYTES bytes)
     */
    uint8 buf[2u * ML_KEM_SSBYTES] = {0};
    /* Will contain key, coins */
    uint8 kr[2u * ML_KEM_SSBYTES] = {0};

    for (auto& testGroup : ML_KEM_encapDecap_testGroups)
    {
        // check for ML-KEM-512 test group and only testgroups with function = decapsulation
        if (("ML-KEM-512" == testGroup.parameterSet) && ("encapsulation" == testGroup.function))
        {
            for (auto& curTest : testGroup.tests)
            {

                // get cypher text from NIST testvectors
                std::size_t len = 0;
                uint8_t* cypherText = hexStringToUint8Array(curTest.c, len);
                ASSERT_NE(cypherText, nullptr);
                ASSERT_EQ(len, CRYPTO_CIPHERTEXTBYTES);
                crc32_ciphertext_temp = crc32(cypherText, CRYPTO_CIPHERTEXTBYTES);

                // build byte array for shared secret (ss_bob)
                std::size_t kLen = 0;
                uint8_t* ssBobNist = hexStringToUint8Array(curTest.k, kLen);
                ASSERT_NE(ssBobNist, nullptr);
                ASSERT_EQ(kLen, ML_KEM_SYMBYTES);
                crc32_sharedsecret_temp = crc32(ssBobNist, ML_KEM_SYMBYTES);

                // build byte array for encapsulation key (pk_bob))
                std::size_t ekBobLen = 0;
                uint8_t* ekBob = hexStringToUint8Array(curTest.ek, ekBobLen);
                ASSERT_NE(ekBob, nullptr);
                ASSERT_EQ(ekBobLen, CRYPTO_PUBLICKEYBYTES);  // match size

                std::size_t mlen = 0;
                uint8_t* m = hexStringToUint8Array(curTest.m, mlen);
                ASSERT_NE(m, nullptr);
                ASSERT_EQ(mlen, ML_KEM_SYMBYTES);

                // provide deterministic seed via the test RNG override
                {
                    ModuleTestRngOverride rng(m, ML_KEM_SYMBYTES);
                    // reproduce internals because curTest.k is not the shared secret, but it matches kr
                    // instead of: ML_KEM_512_Crypto_Kem_Enc(ct, ss_bob, ekBob);

                    (void)FsmSw_CommonLib_RandomBytes(buf, ML_KEM_SYMBYTES);
                    /* Multitarget countermeasure for coins + contributory KEM */
                    FsmSw_Fips202_Sha3_256(&buf[ML_KEM_SYMBYTES], ekBob, ML_KEM_512_PUBLICKEYBYTES);
                    FsmSw_Fips202_Sha3_512(kr, buf, 2u * ML_KEM_SYMBYTES);

                    /* coins are in kr[ML_KEM_SYMBYTES] */
                    ML_KEM_512_Indcpa_Enc(ct, buf, ekBob, &kr[ML_KEM_SYMBYTES]);
                }
                crc32_ciphertext = crc32(ct, CRYPTO_CIPHERTEXTBYTES);
                crc32_sharedsecret_bob = crc32(kr, CRYPTO_ML_KEM_SSBYTES);

                EXPECT_EQ(crc32_ciphertext, crc32_ciphertext_temp);
                EXPECT_EQ(crc32_sharedsecret_bob, crc32_sharedsecret_temp);

                // clean up dyn. memory allocs
                delete[] m;
                m = nullptr;
                delete[] ekBob;
                ekBob = nullptr;
                delete[] ssBobNist;
                ssBobNist = nullptr;
                delete[] cypherText;
                cypherText = nullptr;
            }
        }
    }
}
/***********************************************************************************************************************
 * Name:        ML_KEM_512_Legacy_TEST.GenCipherTxtAndSharedSecretAlice1Tr
 *
 * Description: Test should check the value of the cipher text and the shared secret of alice.
 *
 **********************************************************************************************************************/
TEST(ML_KEM_512_Legacy_TEST, GenCipherTxtAndSharedSecretAlice1Tr)
{
    /*
     * Arguments:   -       uint8 *ct:       pointer to output cipher text (of length CRYPTO_CIPHERTEXTBYTES bytes)
     *              -       uint8 *ss_alice: pointer to output shared secret (of length CRYPTO_ML_KEM_SSBYTES bytes)
     *              - const uint8 *pk_bob:   pointer to input public key (of length CRYPTO_PUBLICKEYBYTES bytes)
     */
    uint8 buf[2u * ML_KEM_SSBYTES] = {0};
    /* Will contain key, coins */
    uint8 kr[2u * ML_KEM_SSBYTES] = {0};

    for (auto& testGroup : ML_KEM_encapDecap_tr1_testGroups)
    {
        // check for ML-KEM-512 test group and only testgroups with function = decapsulation
        if (("ML-KEM-512" == testGroup.parameterSet) && ("encapsulation" == testGroup.function))
        {
            for (auto& curTest : testGroup.tests)
            {

                // get cypher text from NIST testvectors
                std::size_t len = 0;
                uint8_t* cypherText = hexStringToUint8Array(curTest.c, len);
                ASSERT_NE(cypherText, nullptr);
                ASSERT_EQ(len, CRYPTO_CIPHERTEXTBYTES);
                crc32_ciphertext_temp = crc32(cypherText, CRYPTO_CIPHERTEXTBYTES);

                // build byte array for shared secret (ss_bob)
                std::size_t kLen = 0;
                uint8_t* ssBobNist = hexStringToUint8Array(curTest.k, kLen);
                ASSERT_NE(ssBobNist, nullptr);
                ASSERT_EQ(kLen, ML_KEM_SYMBYTES);
                crc32_sharedsecret_temp = crc32(ssBobNist, ML_KEM_SYMBYTES);

                // build byte array for encapsulation key (pk_bob))
                std::size_t ekBobLen = 0;
                uint8_t* ekBob = hexStringToUint8Array(curTest.ek, ekBobLen);
                ASSERT_NE(ekBob, nullptr);
                ASSERT_EQ(ekBobLen, CRYPTO_PUBLICKEYBYTES);  // match size

                std::size_t mlen = 0;
                uint8_t* m = hexStringToUint8Array(curTest.m, mlen);
                ASSERT_NE(m, nullptr);
                ASSERT_EQ(mlen, ML_KEM_SYMBYTES);

                // provide deterministic seed via the test RNG override
                {
                    ModuleTestRngOverride rng(m, ML_KEM_SYMBYTES);
                    // reproduce internals because curTest.k is not the shared secret, but it matches kr
                    // instead of: ML_KEM_512_Crypto_Kem_Enc(ct, ss_bob, ekBob);

                    (void)FsmSw_CommonLib_RandomBytes(buf, ML_KEM_SYMBYTES);
                    /* Multitarget countermeasure for coins + contributory KEM */
                    FsmSw_Fips202_Sha3_256(&buf[ML_KEM_SYMBYTES], ekBob, ML_KEM_512_PUBLICKEYBYTES);
                    FsmSw_Fips202_Sha3_512(kr, buf, 2u * ML_KEM_SYMBYTES);

                    /* coins are in kr[ML_KEM_SYMBYTES] */
                    ML_KEM_512_Indcpa_Enc(ct, buf, ekBob, &kr[ML_KEM_SYMBYTES]);
                }
                crc32_ciphertext = crc32(ct, CRYPTO_CIPHERTEXTBYTES);
                crc32_sharedsecret_bob = crc32(kr, CRYPTO_ML_KEM_SSBYTES);

                EXPECT_EQ(crc32_ciphertext, crc32_ciphertext_temp);
                EXPECT_EQ(crc32_sharedsecret_bob, crc32_sharedsecret_temp);

                // clean up dyn. memory allocs
                delete[] m;
                m = nullptr;
                delete[] ekBob;
                ekBob = nullptr;
                delete[] ssBobNist;
                ssBobNist = nullptr;
                delete[] cypherText;
                cypherText = nullptr;
            }
        }
    }
}

/***********************************************************************************************************************
 * Name:        ML_KEM_512_Legacy_TEST.GenSharedSecretForCipherTxtAndPrivateKeyBob
 *
 * Description: Test should check the decription of the shared secret from bob and the default shared secret.
 *
 **********************************************************************************************************************/
TEST(ML_KEM_512_Legacy_TEST, GenSharedSecretForCipherTxtAndPrivateKeyBob)
{
    /*
     * Arguments:   -       uint8 *ss_alice: pointer to output shared secret (of length CRYPTO_ML_KEM_SSBYTES bytes)
     *              - const uint8 *ct:       pointer to input cipher text (of length CRYPTO_CIPHERTEXTBYTES bytes)
     *              - const uint8 *sk_alice: pointer to input private key (of length CRYPTO_SECRETKEYBYTES bytes)
     */
    uint32 i = 0;
    uint8 fail = 0;
    uint8 buf[2u * ML_KEM_SSBYTES] = {0};
    /* Will contain key, coins */
    uint8 kr[2u * ML_KEM_SSBYTES] = {0};
    uint8 cmp[CRYPTO_CIPHERTEXTBYTES] = {0};

    for (auto& testGroup : ML_KEM_encapDecap_testGroups)
    {
        // check for ML-KEM-512 test group and only testgroups with function = decapsulation
        if (("ML-KEM-512" == testGroup.parameterSet) && ("decapsulation" == testGroup.function))
        {
            for (auto& curTest : testGroup.tests)
            {
                // skip tests that are not valid
                if ("valid decapsulation" != curTest.reason)
                {
                    continue;
                }
                // get cypher text from NIST testvectors
                std::size_t len = 0;
                uint8_t* cypherText = hexStringToUint8Array(curTest.c, len);
                ASSERT_NE(cypherText, nullptr);
                ASSERT_EQ(len, CRYPTO_CIPHERTEXTBYTES);

                // build byte array for decapsulation key (sk_alice)
                std::size_t dkLen = 0;
                uint8_t* dkAlice = hexStringToUint8Array(curTest.dk, dkLen);
                ASSERT_NE(dkAlice, nullptr);
                ASSERT_EQ(dkLen, CRYPTO_SECRETKEYBYTES);

                // build byte array for shared secret k (ss_bob)
                std::size_t kBobLen = 0;
                uint8_t* kBob = hexStringToUint8Array(curTest.k, kBobLen);
                ASSERT_NE(kBob, nullptr);
                ASSERT_EQ(kBobLen, CRYPTO_ML_KEM_SSBYTES);  // match size
                crc32_sharedsecret_bob = crc32(kBob, CRYPTO_ML_KEM_SSBYTES);

                // calculate shared secret ss_alice from the given cyphertext and the decapsulation key from alice
                // ML_KEM_512_Crypto_Kem_Dec(ss_alice, cypherText, dkAlice);
                // reproduce internals because curTest.k is not the shared secret, but it matches kr
                ML_KEM_512_Indcpa_Dec(buf, cypherText, dkAlice);

                /* Multitarget countermeasure for coins + contributory KEM */
                for (i = 0; i < CRYPTO_ML_KEM_SSBYTES; i++)
                {
                    buf[CRYPTO_ML_KEM_SSBYTES + i] = dkAlice[CRYPTO_SECRETKEYBYTES - (2u * CRYPTO_ML_KEM_SSBYTES) + i];
                }

                FsmSw_Fips202_Sha3_512(kr, buf, 2u * CRYPTO_ML_KEM_SSBYTES);

                crc32_sharedsecret_alice = crc32(kr, CRYPTO_ML_KEM_SSBYTES);

                // both shared secrets (from the NIST test vector and the calculated ss_alice should be equal
                // -> crc32 of them is equal
                EXPECT_EQ(crc32_sharedsecret_alice, crc32_sharedsecret_bob);

                // clean up dynamic memory allocation
                delete[] cypherText;
                cypherText = nullptr;
                delete[] dkAlice;
                dkAlice = nullptr;
                delete[] kBob;
                kBob = nullptr;
            }
        }
    }
}

/***********************************************************************************************************************
 * Name:        ML_KEM_512_Legacy_TEST.GenSharedSecretForCipherTxtAndPrivateKeyBob1Tr
 *
 * Description: Test should check the decription of the shared secret from bob and the default shared secret.
 *
 **********************************************************************************************************************/
TEST(ML_KEM_512_Legacy_TEST, GenSharedSecretForCipherTxtAndPrivateKeyBob1Tr)
{
    /*
     * Arguments:   -       uint8 *ss_alice: pointer to output shared secret (of length CRYPTO_ML_KEM_SSBYTES bytes)
     *              - const uint8 *ct:       pointer to input cipher text (of length CRYPTO_CIPHERTEXTBYTES bytes)
     *              - const uint8 *sk_alice: pointer to input private key (of length CRYPTO_SECRETKEYBYTES bytes)
     */
    uint32 i = 0;
    uint8 fail = 0;
    uint8 buf[2u * ML_KEM_SSBYTES] = {0};
    /* Will contain key, coins */
    uint8 kr[2u * ML_KEM_SSBYTES] = {0};
    uint8 cmp[CRYPTO_CIPHERTEXTBYTES] = {0};

    for (auto& testGroup : ML_KEM_encapDecap_tr1_testGroups)
    {
        // check for ML-KEM-512 test group and only testgroups with function = decapsulation
        if (("ML-KEM-512" == testGroup.parameterSet) && ("decapsulation" == testGroup.function))
        {
            for (auto& curTest : testGroup.tests)
            {
                // skip tests that are not valid
                if ("valid decapsulation" != curTest.reason)
                {
                    continue;
                }
                // get cypher text from NIST testvectors
                std::size_t len = 0;
                uint8_t* cypherText = hexStringToUint8Array(curTest.c, len);
                ASSERT_NE(cypherText, nullptr);
                ASSERT_EQ(len, CRYPTO_CIPHERTEXTBYTES);

                // build byte array for decapsulation key (sk_alice)
                std::size_t dkLen = 0;
                uint8_t* dkAlice = hexStringToUint8Array(curTest.dk, dkLen);
                ASSERT_NE(dkAlice, nullptr);
                ASSERT_EQ(dkLen, CRYPTO_SECRETKEYBYTES);

                // build byte array for shared secret k (ss_bob)
                std::size_t kBobLen = 0;
                uint8_t* kBob = hexStringToUint8Array(curTest.k, kBobLen);
                ASSERT_NE(kBob, nullptr);
                ASSERT_EQ(kBobLen, CRYPTO_ML_KEM_SSBYTES);  // match size
                crc32_sharedsecret_bob = crc32(kBob, CRYPTO_ML_KEM_SSBYTES);

                // calculate shared secret ss_alice from the given cyphertext and the decapsulation key from alice
                // ML_KEM_512_Crypto_Kem_Dec(ss_alice, cypherText, dkAlice);
                // reproduce internals because curTest.k is not the shared secret, but it matches kr
                ML_KEM_512_Indcpa_Dec(buf, cypherText, dkAlice);

                /* Multitarget countermeasure for coins + contributory KEM */
                for (i = 0; i < CRYPTO_ML_KEM_SSBYTES; i++)
                {
                    buf[CRYPTO_ML_KEM_SSBYTES + i] = dkAlice[CRYPTO_SECRETKEYBYTES - (2u * CRYPTO_ML_KEM_SSBYTES) + i];
                }

                FsmSw_Fips202_Sha3_512(kr, buf, 2u * CRYPTO_ML_KEM_SSBYTES);

                crc32_sharedsecret_alice = crc32(kr, CRYPTO_ML_KEM_SSBYTES);

                // both shared secrets (from the NIST test vector and the calculated ss_alice should be equal
                // -> crc32 of them is equal
                EXPECT_EQ(crc32_sharedsecret_alice, crc32_sharedsecret_bob);

                // clean up dynamic memory allocation
                delete[] cypherText;
                cypherText = nullptr;
                delete[] dkAlice;
                dkAlice = nullptr;
                delete[] kBob;
                kBob = nullptr;
            }
        }
    }
}
