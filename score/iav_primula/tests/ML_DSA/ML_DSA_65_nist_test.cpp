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

#include "ML_DSA_keyGenFIPS204_testData.h"
#include "ML_DSA_sigGenFIPS204Tr1_testData.h"
#include "ML_DSA_sigGenFIPS204_testData.h"
#include "ML_DSA_sigVerFIPS204_testData.h"

#include "module_test_support.h"
#include "test_helpers.h"
#include <gtest/gtest.h>

extern "C" {
#include "ML_DSA_65_api.h"
#include "crc32.h"
}

/**********************************************************************************************************************/
/* DEFINES                                                                                                            */
/**********************************************************************************************************************/
#define ERR_OK 0u
#define ERR_NOT_OK 1u
#define TEST_SUCCESS ERR_OK

#define CRYPTO_PUBLICKEYBYTES FSMSW_ML_DSA_65_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES FSMSW_ML_DSA_65_CRYPTO_SECRETKEYBYTES
#define CRYPTO_BYTES FSMSW_ML_DSA_65_CRYPTO_BYTES
#define CRYPTO_SEED_LEN 32
#define CRYPTO_MAX_MSG_SIZE 16384  // big array due to long messages of unknown size

#define crypto_sign_keypair ML_DSA_65_Crypto_Sign_KeyPair
#define crypto_sign_signature ML_DSA_65_Crypto_Sign_Signature
#define crypto_sign_verify ML_DSA_65_Crypto_Sign_Verify_Ctx
#define crypto_sign ML_DSA_65_Crypto_Sign_Ctx
#define crypto_sign_open ML_DSA_65_Crypto_Sign_Open_Ctx

/**********************************************************************************************************************/
/* MODULE GLOBAL VARIABLES                                                                                            */
/**********************************************************************************************************************/
static uint8 retVal;
static uint8 sig[CRYPTO_BYTES];
static uint8 sk[CRYPTO_SECRETKEYBYTES];
static uint8 pk[CRYPTO_PUBLICKEYBYTES];
static uint32 siglen;
static uint32 smlen;
static uint32 crc32_pk;
static uint32 crc32_sk;
static uint32 crc32_sig;
static uint32 crc32_pk_temp;
static uint32 crc32_sk_temp;
static uint32 crc32_sig_temp;
static uint8 sm[CRYPTO_BYTES + CRYPTO_MAX_MSG_SIZE];  // buffer for msg and signature,
static uint8 mout[CRYPTO_MAX_MSG_SIZE];
static uint32 moutlen;

/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/

/*
 * Info: - As these are smoke tests, a single test for the required process would be very confusing. It was therefore
 *         decided to write small individual test cases in a test suite, which can depend on each other.
 *       - Function crc32() is used to generate a crc32 signature for various arrays. The temporary signature is used in
 *         the individual tests as a reference value for the signature of the source code arrays.
 */

/***********************************************************************************************************************
 * Name:        ML_DSA_65_TEST.CreatePkAndSk
 *
 * Description: Test should check the value of public and private key
 *
 ***********************************************************************************************************************/
TEST(ML_DSA_65_Nist_TEST, CreatePkAndSk)
{
    /*
     * Arguments:   - uint8 *pk: pointer to output public key
     *              - uint8 *sk: pointer to output private key
     */
    for (auto& testGroup : ML_DSA_keyGen_testGroups)
    {
        // check for ml_dsa_44 test group
        if ("ML-DSA-65" == testGroup.parameterSet)
        {
            for (auto& curTest : testGroup.tests)
            {
                // get sk and pk from NIST testvectors
                // build byte arrays for sk
                std::size_t len = 0;
                uint8_t* skNist = hexStringToUint8Array(curTest.sk, len);
                ASSERT_NE(skNist, nullptr);
                ASSERT_EQ(len, CRYPTO_SECRETKEYBYTES);  // match size

                // build byte arrays for pk
                uint8_t* pkNist = hexStringToUint8Array(curTest.pk, len);
                ASSERT_NE(pkNist, nullptr);
                ASSERT_EQ(len, CRYPTO_PUBLICKEYBYTES);  // match size

                // calculate crc32 from NIST keys for later comparison with generated pk/sk with supplied seed
                crc32_sk_temp = crc32(skNist, CRYPTO_SECRETKEYBYTES);
                crc32_pk_temp = crc32(pkNist, CRYPTO_PUBLICKEYBYTES);

                uint8_t* seedNist = hexStringToUint8Array(curTest.seed, len);
                ASSERT_NE(seedNist, nullptr);
                ASSERT_EQ(len, CRYPTO_SEED_LEN);

                // provide deterministic seed to keypair via RandomBytes wrapper
                {
                    ModuleTestRngOverride rng(seedNist, len);
                    // generate pk and sk from given seed
                    crypto_sign_keypair(pk, sk);
                }  // calculate crc32 from generated pk/sk with supplied seed
                crc32_sk = crc32(sk, CRYPTO_SECRETKEYBYTES);
                crc32_pk = crc32(pk, CRYPTO_PUBLICKEYBYTES);

                EXPECT_EQ(crc32_pk, crc32_pk_temp);
                EXPECT_EQ(crc32_sk, crc32_sk_temp);

                // clean up dyn allocated memory
                delete[] skNist;
                skNist = nullptr;
                delete[] pkNist;
                pkNist = nullptr;
                delete[] seedNist;
                seedNist = nullptr;
            }
        }
    }
}

/***********************************************************************************************************************
 * Name:        ML_DSA_65_TEST.CreateSignature
 *
 * Description: Test should check the value of signature
 *
 ***********************************************************************************************************************/
TEST(ML_DSA_65_Nist_TEST, CreateSignature)
{
    for (auto& testGroup : ML_DSA_sigGen_testGroups)
    {
        // check for ml_dsa_65 test group and only testgroups with signatureInterface = external and preHash = pure
        if (("ML-DSA-65" == testGroup.parameterSet) && ("pure" == testGroup.preHash) &&
            ("external" == testGroup.signatureInterface))
        {
            for (auto& curTest : testGroup.tests)
            {
                // skip tests that are not relevant
                if ("" != curTest.mu)
                {
                    continue;
                }
                if ("" != curTest.rnd)
                {
                    continue;
                }
                if ("" != curTest.context)
                {
                    continue;
                }
                // try the testcases which uses no extra hashAlg, otherwise skip it as we don't have a way to handle it
                // yet.
                if (curTest.hashAlg != "none")
                {
                    continue;
                }

                std::size_t len = 0;
                uint8_t* sigNist = hexStringToUint8Array(curTest.signature, len);
                ASSERT_NE(sigNist, nullptr);
                ASSERT_EQ(len, CRYPTO_BYTES);
                crc32_sig_temp = crc32(sigNist, CRYPTO_BYTES);

                // build byte arrays for message
                std::size_t msgNistLen = 0;
                uint8_t* msgNist = hexStringToUint8Array(curTest.message, msgNistLen);
                ASSERT_NE(msgNist, nullptr);
                ASSERT_NE(msgNistLen, 0);

                // build byte array for secret key
                uint8_t* skNist = hexStringToUint8Array(curTest.sk, len);
                ASSERT_NE(skNist, nullptr);
                ASSERT_EQ(len, CRYPTO_SECRETKEYBYTES);  // match size

                crypto_sign_signature(sig, &siglen, msgNist, msgNistLen, skNist);
                crc32_sig = crc32(sig, CRYPTO_BYTES);

                // clean up dynamic memory allocation
                delete[] msgNist;
                msgNist = nullptr;
                delete[] skNist;
                skNist = nullptr;
                delete[] sigNist;
                sigNist = nullptr;

                EXPECT_EQ(crc32_sig, crc32_sig_temp);
            }
        }
    }
}

/***********************************************************************************************************************
 * Name:        ML_DSA_65_TEST.CreateSignatureTr1
 *
 * Description: Test should check the value of signature
 *
 ***********************************************************************************************************************/
TEST(ML_DSA_65_Nist_TEST, CreateSignatureTr1)
{
    for (auto& testGroup : ML_DSA_sigGen_tr1_testGroups)
    {
        // check for ml_dsa_65 test group and only testgroups with signatureInterface = external and preHash = pure
        if (("ML-DSA-65" == testGroup.parameterSet) && ("pure" == testGroup.preHash) &&
            ("external" == testGroup.signatureInterface))
        {
            for (auto& curTest : testGroup.tests)
            {
                // skip tests that are not relevant
                if ("" != curTest.mu)
                {
                    continue;
                }
                if ("" != curTest.rnd)
                {
                    continue;
                }
                if ("" != curTest.context)
                {
                    continue;
                }
                // try the testcases which uses no extra hashAlg, otherwise skip it as we don't have a way to handle it
                // yet.
                if (curTest.hashAlg != "none")
                {
                    continue;
                }

                std::size_t len = 0;
                uint8_t* sigNist = hexStringToUint8Array(curTest.signature, len);
                ASSERT_NE(sigNist, nullptr);
                ASSERT_EQ(len, CRYPTO_BYTES);
                crc32_sig_temp = crc32(sigNist, CRYPTO_BYTES);

                // build byte arrays for message
                std::size_t msgNistLen = 0;
                uint8_t* msgNist = hexStringToUint8Array(curTest.message, msgNistLen);
                ASSERT_NE(msgNist, nullptr);
                ASSERT_NE(msgNistLen, 0);

                // build byte array for secret key
                uint8_t* skNist = hexStringToUint8Array(curTest.sk, len);
                ASSERT_NE(skNist, nullptr);
                ASSERT_EQ(len, CRYPTO_SECRETKEYBYTES);  // match size

                crypto_sign_signature(sig, &siglen, msgNist, msgNistLen, skNist);
                crc32_sig = crc32(sig, CRYPTO_BYTES);

                // clean up dynamic memory allocation
                delete[] msgNist;
                msgNist = nullptr;
                delete[] skNist;
                skNist = nullptr;
                delete[] sigNist;
                sigNist = nullptr;

                EXPECT_EQ(crc32_sig, crc32_sig_temp);
            }
        }
    }
}

/***********************************************************************************************************************
 * Name:        ML_DSA_65_TEST.VerifiesSignature
 *
 * Description: Test should check that the function ML_DSA_44_Crypto_Sign_Verify returns 0 (signature has been
 *              verified correctly)
 *
 ***********************************************************************************************************************/
TEST(ML_DSA_65_Nist_TEST, VerifiesSignature)
{
    /*
     * Arguments:   -       uint8  *m:      pointer to input signature
     *              -       uint32  siglen: length of signature
     *              - const uint8  *m:      pointer to message
     *              -       uint32  mlen:   length of message
     *              - const uint8  *pk:     pointer to bit-packed public key
     */

    uint8_t retVal;

    for (auto& testGroup : ML_DSA_sigVer_testGroups)
    {
        // check for ml_dsa_44 test group and only testgroups with signatureInterface = external and preHash = pure
        if (("ML-DSA-65" == testGroup.parameterSet) && ("pure" == testGroup.preHash) &&
            ("external" == testGroup.signatureInterface))
        {
            for (auto& curTest : testGroup.tests)
            {
                // skip tests that are not passed
                if (false == curTest.testPassed)
                {
                    continue;
                }
                // try the testcases which uses no extra hashAlg, otherwise skip it as we don't have a way to handle it
                // yet.
                if (curTest.hashAlg != "none")
                {
                    continue;
                }

                // get context if != ""
                uint8_t* conNist = nullptr;
                std::size_t conNistLen = 0;

                if (curTest.context != "")
                {
                    conNist = hexStringToUint8Array(curTest.context, conNistLen);
                    ASSERT_NE(conNist, nullptr);
                }

                std::size_t len = 0;
                uint8_t* sigNist = hexStringToUint8Array(curTest.signature, len);
                ASSERT_NE(sigNist, nullptr);
                ASSERT_EQ(len, CRYPTO_BYTES);

                // build byte arrays for message
                std::size_t msgNistLen = 0;
                uint8_t* msgNist = hexStringToUint8Array(curTest.message, msgNistLen);
                ASSERT_NE(msgNist, nullptr);
                ASSERT_NE(msgNistLen, 0);

                // build byte arrays for pk
                uint8_t* pkNist = hexStringToUint8Array(curTest.pk, len);
                ASSERT_NE(pkNist, nullptr);
                ASSERT_EQ(len, CRYPTO_PUBLICKEYBYTES);  // match size

                retVal = crypto_sign_verify(sigNist, CRYPTO_BYTES, msgNist, msgNistLen, conNist, conNistLen, pkNist);

                // clean up dynamic memory allocation
                delete[] msgNist;
                msgNist = nullptr;
                delete[] pkNist;
                pkNist = nullptr;
                delete[] sigNist;
                sigNist = nullptr;
                if (conNist != nullptr)
                {
                    delete[] conNist;
                    conNist = nullptr;
                }

                EXPECT_EQ(retVal, TEST_SUCCESS);
            }
        }
    }
}

/***********************************************************************************************************************
 * Name:        ML_DSA_65_TEST.ComputeSignedMessage
 *
 * Description: Test should check the value of computed signed message and verify it with pk.
 *
 ***********************************************************************************************************************/
TEST(ML_DSA_65_Nist_TEST, ComputeSignedMessage)
{
    for (auto& testGroup : ML_DSA_sigVer_testGroups)
    {
        // check for ml_dsa_65 test group and only testgroups with signatureInterface = external and preHash = pure
        if (("ML-DSA-65" == testGroup.parameterSet) && ("pure" == testGroup.preHash) &&
            ("external" == testGroup.signatureInterface))
        {
            for (auto& curTest : testGroup.tests)
            {
                // skip tests that are not passed
                if (false == curTest.testPassed)
                {
                    continue;
                }
                // try the testcases which uses no extra hashAlg, otherwise skip it as we don't have a way to handle it
                // yet.
                if (curTest.hashAlg != "none")
                {
                    continue;
                }

                // get context if != ""
                uint8_t* conNist = nullptr;
                std::size_t conNistLen = 0;

                if (curTest.context != "")
                {
                    conNist = hexStringToUint8Array(curTest.context, conNistLen);
                    ASSERT_NE(conNist, nullptr);
                }

                std::size_t len = 0;
                uint8_t* sigNist = hexStringToUint8Array(curTest.signature, len);
                ASSERT_NE(sigNist, nullptr);
                ASSERT_EQ(len, CRYPTO_BYTES);

                // build byte arrays for message
                std::size_t msgNistLen = 0;
                uint8_t* msgNist = hexStringToUint8Array(curTest.message, msgNistLen);
                ASSERT_NE(msgNist, nullptr);
                ASSERT_NE(msgNistLen, 0);

                // build byte arrays for sk
                uint8_t* skNist = hexStringToUint8Array(curTest.sk, len);
                ASSERT_NE(skNist, nullptr);
                ASSERT_EQ(len, CRYPTO_SECRETKEYBYTES);  // match size

                retVal = crypto_sign(sm, &smlen, msgNist, msgNistLen, conNist, conNistLen, skNist);
                EXPECT_EQ(retVal, ERR_OK);

                // VerifySignedMessage
                // build byte array for pk
                uint8_t* pkNist = hexStringToUint8Array(curTest.pk, len);
                ASSERT_NE(pkNist, nullptr);
                ASSERT_EQ(len, CRYPTO_PUBLICKEYBYTES);  // match size

                retVal = crypto_sign_open(mout, &moutlen, sm, smlen, conNist, conNistLen, pkNist);
                EXPECT_EQ(retVal, ERR_OK);
                EXPECT_EQ(moutlen, msgNistLen);

                // clean up dynamic memory allocation
                delete[] msgNist;
                msgNist = nullptr;
                delete[] skNist;
                skNist = nullptr;
                delete[] sigNist;
                sigNist = nullptr;
                delete[] pkNist;
                pkNist = nullptr;
                if (conNist != nullptr)
                {
                    delete[] conNist;
                    conNist = nullptr;
                }
            }
        }
    }
}
