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

#include "iav_primula_ffi.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace
{

constexpr std::uint8_t kCanary = 0xA5U;
constexpr std::uint8_t kChangedByte = 0x01U;
constexpr std::uint8_t kDecapsulatedSecretCanary = 0x5AU;

struct CountingDeleter
{
    std::size_t* destructions{};

    void operator()(iav_primula_key_handle* const key) const noexcept
    {
        if (key != nullptr)
        {
            iav_key_destroy(key);
            ++*destructions;
        }
    }
};

using OwnedKey = std::unique_ptr<iav_primula_key_handle, CountingDeleter>;

struct SignatureCase
{
    const char* name;
    iav_algorithm algorithm;
    std::size_t public_key_length;
    std::size_t signature_length;
};

struct KemCase
{
    const char* name;
    iav_algorithm algorithm;
    std::size_t public_key_length;
    std::size_t ciphertext_length;
    std::size_t shared_secret_length;
};

TEST(IavPrimulaFfiTest, PreservesNumericAbiValues)
{
    EXPECT_EQ(static_cast<std::uint32_t>(IavStatusOk), 0U);
    EXPECT_EQ(static_cast<std::uint32_t>(IavStatusInvalidArgument), 1U);
    EXPECT_EQ(static_cast<std::uint32_t>(IavStatusBufferTooSmall), 2U);
    EXPECT_EQ(static_cast<std::uint32_t>(IavStatusUnsupportedAlgorithm), 3U);
    EXPECT_EQ(static_cast<std::uint32_t>(IavStatusVerificationFailed), 4U);
    EXPECT_EQ(static_cast<std::uint32_t>(IavStatusCryptoFailure), 5U);

    EXPECT_EQ(static_cast<std::uint32_t>(IavAlgorithmMlDsa44), 1U);
    EXPECT_EQ(static_cast<std::uint32_t>(IavAlgorithmMlDsa65), 2U);
    EXPECT_EQ(static_cast<std::uint32_t>(IavAlgorithmMlDsa87), 3U);
    EXPECT_EQ(static_cast<std::uint32_t>(IavAlgorithmMlKem512), 10U);
    EXPECT_EQ(static_cast<std::uint32_t>(IavAlgorithmMlKem768), 11U);
    EXPECT_EQ(static_cast<std::uint32_t>(IavAlgorithmMlKem1024), 12U);
}

TEST(IavPrimulaFfiTest, AllMlDsaVariantsGenerateSignAndVerifyWithinAbiCapacities)
{
    constexpr SignatureCase cases[] = {{"ML-DSA-44", IavAlgorithmMlDsa44, 1312U, 2420U},
                                       {"ML-DSA-65", IavAlgorithmMlDsa65, 1952U, 3309U},
                                       {"ML-DSA-87", IavAlgorithmMlDsa87, 2592U, 4627U}};
    constexpr std::uint8_t message[] = {
        0x49U, 0x41U, 0x56U, 0x2DU, 0x50U, 0x72U, 0x69U, 0x6DU, 0x75U, 0x6CU, 0x61U, 0x21U, 0x00U};

    for (const SignatureCase& test_case : cases)
    {
        SCOPED_TRACE(test_case.name);
        std::size_t destructions = 0U;
        OwnedKey key{nullptr, CountingDeleter{&destructions}};
        iav_primula_key_handle* generated = nullptr;
        const iav_status generation_status = iav_keypair_generate(test_case.algorithm, &generated);
        key.reset(generated);
        ASSERT_EQ(generation_status, IavStatusOk);
        ASSERT_NE(key, nullptr);

        std::vector<std::uint8_t> undersized_public_key(test_case.public_key_length, kCanary);
        const std::size_t public_key_capacity = test_case.public_key_length - 1U;
        std::size_t undersized_public_key_length = public_key_capacity;
        EXPECT_EQ(iav_public_key_export(key.get(), undersized_public_key.data(), &undersized_public_key_length),
                  IavStatusBufferTooSmall);
        EXPECT_EQ(undersized_public_key[public_key_capacity], kCanary);

        std::vector<std::uint8_t> public_key(test_case.public_key_length + 1U);
        std::size_t public_key_length = public_key.size();
        ASSERT_EQ(iav_public_key_export(key.get(), public_key.data(), &public_key_length), IavStatusOk);
        EXPECT_EQ(public_key_length, test_case.public_key_length);

        std::vector<std::uint8_t> undersized_signature(test_case.signature_length, kCanary);
        const std::size_t signature_capacity = test_case.signature_length - 1U;
        std::size_t undersized_signature_length = signature_capacity;
        EXPECT_EQ(
            iav_sign(key.get(), message, sizeof(message), undersized_signature.data(), &undersized_signature_length),
            IavStatusBufferTooSmall);
        EXPECT_EQ(undersized_signature[signature_capacity], kCanary);

        std::vector<std::uint8_t> signature(test_case.signature_length + 1U);
        std::size_t signature_length = signature.size();
        ASSERT_EQ(iav_sign(key.get(), message, sizeof(message), signature.data(), &signature_length), IavStatusOk);
        EXPECT_EQ(signature_length, test_case.signature_length);
        EXPECT_EQ(iav_verify(key.get(), message, sizeof(message), signature.data(), signature_length), IavStatusOk);
        EXPECT_EQ(iav_verify_public_key(test_case.algorithm,
                                        public_key.data(),
                                        public_key_length,
                                        message,
                                        sizeof(message),
                                        signature.data(),
                                        signature_length),
                  IavStatusOk);

        signature[0] ^= kChangedByte;
        EXPECT_EQ(iav_verify(key.get(), message, sizeof(message), signature.data(), signature_length),
                  IavStatusVerificationFailed);

        key.reset();
        EXPECT_EQ(destructions, 1U);
    }
}

TEST(IavPrimulaFfiTest, AllMlKemVariantsEncapsulateAndDecapsulateWithinAbiCapacities)
{
    constexpr KemCase cases[] = {{"ML-KEM-512", IavAlgorithmMlKem512, 800U, 768U, 32U},
                                 {"ML-KEM-768", IavAlgorithmMlKem768, 1184U, 1088U, 32U},
                                 {"ML-KEM-1024", IavAlgorithmMlKem1024, 1568U, 1568U, 32U}};

    for (const KemCase& test_case : cases)
    {
        SCOPED_TRACE(test_case.name);
        std::size_t destructions = 0U;
        OwnedKey key{nullptr, CountingDeleter{&destructions}};
        iav_primula_key_handle* generated = nullptr;
        const iav_status generation_status = iav_kem_keypair_generate(test_case.algorithm, &generated);
        key.reset(generated);
        ASSERT_EQ(generation_status, IavStatusOk);
        ASSERT_NE(key, nullptr);

        std::vector<std::uint8_t> undersized_public_key(test_case.public_key_length, kCanary);
        const std::size_t public_key_capacity = test_case.public_key_length - 1U;
        std::size_t undersized_public_key_length = public_key_capacity;
        EXPECT_EQ(iav_kem_public_key_export(key.get(), undersized_public_key.data(), &undersized_public_key_length),
                  IavStatusBufferTooSmall);
        EXPECT_EQ(undersized_public_key[public_key_capacity], kCanary);

        std::vector<std::uint8_t> public_key(test_case.public_key_length + 1U);
        std::size_t public_key_length = public_key.size();
        ASSERT_EQ(iav_kem_public_key_export(key.get(), public_key.data(), &public_key_length), IavStatusOk);
        EXPECT_EQ(public_key_length, test_case.public_key_length);

        std::vector<std::uint8_t> undersized_ciphertext(test_case.ciphertext_length, kCanary);
        std::vector<std::uint8_t> ciphertext_peer_secret(test_case.shared_secret_length, kCanary);
        const std::size_t ciphertext_capacity = test_case.ciphertext_length - 1U;
        std::size_t undersized_ciphertext_length = ciphertext_capacity;
        std::size_t ciphertext_peer_secret_length = ciphertext_peer_secret.size();
        EXPECT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                      public_key.data(),
                                      public_key_length,
                                      undersized_ciphertext.data(),
                                      &undersized_ciphertext_length,
                                      ciphertext_peer_secret.data(),
                                      &ciphertext_peer_secret_length),
                  IavStatusBufferTooSmall);
        EXPECT_EQ(undersized_ciphertext[ciphertext_capacity], kCanary);

        std::vector<std::uint8_t> peer_ciphertext(test_case.ciphertext_length, kCanary);
        std::vector<std::uint8_t> undersized_shared_secret(test_case.shared_secret_length, kCanary);
        const std::size_t shared_secret_capacity = test_case.shared_secret_length - 1U;
        std::size_t peer_ciphertext_length = peer_ciphertext.size();
        std::size_t undersized_shared_secret_length = shared_secret_capacity;
        EXPECT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                      public_key.data(),
                                      public_key_length,
                                      peer_ciphertext.data(),
                                      &peer_ciphertext_length,
                                      undersized_shared_secret.data(),
                                      &undersized_shared_secret_length),
                  IavStatusBufferTooSmall);
        EXPECT_EQ(undersized_shared_secret[shared_secret_capacity], kCanary);

        std::vector<std::uint8_t> ciphertext(test_case.ciphertext_length + 1U);
        std::vector<std::uint8_t> encapsulated_secret(test_case.shared_secret_length + 1U, kCanary);
        std::size_t ciphertext_length = ciphertext.size();
        std::size_t encapsulated_secret_length = encapsulated_secret.size();
        ASSERT_EQ(iav_kem_encapsulate(test_case.algorithm,
                                      public_key.data(),
                                      public_key_length,
                                      ciphertext.data(),
                                      &ciphertext_length,
                                      encapsulated_secret.data(),
                                      &encapsulated_secret_length),
                  IavStatusOk);
        EXPECT_EQ(ciphertext_length, test_case.ciphertext_length);
        EXPECT_EQ(encapsulated_secret_length, test_case.shared_secret_length);

        std::vector<std::uint8_t> undersized_decapsulated_secret(test_case.shared_secret_length, kCanary);
        std::size_t undersized_decapsulated_secret_length = shared_secret_capacity;
        EXPECT_EQ(iav_kem_decapsulate(key.get(),
                                      ciphertext.data(),
                                      ciphertext_length,
                                      undersized_decapsulated_secret.data(),
                                      &undersized_decapsulated_secret_length),
                  IavStatusBufferTooSmall);
        EXPECT_EQ(undersized_decapsulated_secret[shared_secret_capacity], kCanary);

        std::vector<std::uint8_t> decapsulated_secret(test_case.shared_secret_length + 1U, kDecapsulatedSecretCanary);
        std::size_t decapsulated_secret_length = decapsulated_secret.size();
        ASSERT_EQ(iav_kem_decapsulate(key.get(),
                                      ciphertext.data(),
                                      ciphertext_length,
                                      decapsulated_secret.data(),
                                      &decapsulated_secret_length),
                  IavStatusOk);
        EXPECT_EQ(decapsulated_secret_length, test_case.shared_secret_length);
        ASSERT_LE(encapsulated_secret_length, encapsulated_secret.size());
        ASSERT_LE(decapsulated_secret_length, decapsulated_secret.size());
        EXPECT_TRUE(std::equal(encapsulated_secret.begin(),
                               encapsulated_secret.begin() + encapsulated_secret_length,
                               decapsulated_secret.begin(),
                               decapsulated_secret.begin() + decapsulated_secret_length));

        key.reset();
        EXPECT_EQ(destructions, 1U);
    }
}

}  // namespace
