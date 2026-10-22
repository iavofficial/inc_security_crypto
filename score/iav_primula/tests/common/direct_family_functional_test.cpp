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

/// @file direct_family_functional_test.cpp
/// @brief Functional tests for vendor signature and KEM APIs not routed by the FFI.

#include "score/iav_primula/include/iav_primula_ffi.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <type_traits>
#include <vector>

extern "C" {
#include "FN_DSA_1024_api.h"
#include "FN_DSA_512_api.h"
#include "FsmSw_CommonLib.h"
#include "Hqc128_api.h"
#include "Hqc192_api.h"
#include "Hqc256_api.h"
#include "Hqc_api.h"
#include "SLH_DSA_SHA2_128fSimple_api.h"
#include "SLH_DSA_SHA2_128sSimple_api.h"
#include "SLH_DSA_SHA2_192fSimple_api.h"
#include "SLH_DSA_SHA2_192sSimple_api.h"
#include "SLH_DSA_SHA2_256fSimple_api.h"
#include "SLH_DSA_SHA2_256sSimple_api.h"
#include "SLH_DSA_SHAKE_128fSimple_api.h"
#include "SLH_DSA_SHAKE_128sSimple_api.h"
#include "SLH_DSA_SHAKE_192fSimple_api.h"
#include "SLH_DSA_SHAKE_192sSimple_api.h"
#include "SLH_DSA_SHAKE_256fSimple_api.h"
#include "SLH_DSA_SHAKE_256sSimple_api.h"
#include "score/iav_primula/include/Platform_Types.h"
}

namespace
{

struct TestRngContext
{
    std::atomic<std::uint64_t> request_counter{0U};
};

constexpr std::uint64_t kSplitMixGamma = 0x9E3779B97F4A7C15ULL;
constexpr std::uint64_t kSplitMixMultiplier1 = 0xBF58476D1CE4E5B9ULL;
constexpr std::uint64_t kSplitMixMultiplier2 = 0x94D049BB133111EBULL;
constexpr unsigned int kSplitMixShift1 = 30U;
constexpr unsigned int kSplitMixShift2 = 27U;
constexpr unsigned int kSplitMixShift3 = 31U;
constexpr unsigned int kOutputByteShift = 56U;
constexpr std::size_t kDirectSignatureVariantCount = 14U;
constexpr std::size_t kDirectKemVariantCount = 3U;

/// This deterministic provider is test-only; production targets never depend on it.
int FillTestRandomBytes(std::uint8_t* output, std::size_t output_len, void* user_data)
{
    auto* const context = static_cast<TestRngContext*>(user_data);
    if (context == nullptr || (output == nullptr && output_len != 0U))
    {
        return 1;
    }

    const std::uint64_t request = context->request_counter.fetch_add(1U, std::memory_order_relaxed);
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic): fill the C callback's caller-provided byte span.
    for (std::size_t index = 0U; index < output_len; ++index)
    {
        std::uint64_t value = request + kSplitMixGamma * (index + 1U);
        value = (value ^ (value >> kSplitMixShift1)) * kSplitMixMultiplier1;
        value = (value ^ (value >> kSplitMixShift2)) * kSplitMixMultiplier2;
        value ^= value >> kSplitMixShift3;
        output[index] = static_cast<std::uint8_t>(value >> kOutputByteShift);
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return 0;
}

TestRngContext& GetTestRngContext()
{
    static TestRngContext context;
    return context;
}

iav_status RegisterTestRandomBytesProvider()
{
    static const iav_status status = iav_random_bytes_provider_register(FillTestRandomBytes, &GetTestRngContext());
    return status;
}

class GuardedBuffer
{
  public:
    explicit GuardedBuffer(std::size_t capacity)
        : capacity_(capacity), storage_(kPrefixSize + capacity + kSuffixSize, kCanary)
    {
    }

    std::uint8_t* data()
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): expose the guarded byte span.
        return storage_.data() + kPrefixSize;
    }

    bool CanariesIntact() const
    {
        for (std::size_t index = 0U; index < kPrefixSize; ++index)
        {
            if (storage_[index] != kCanary)
            {
                return false;
            }
        }
        for (std::size_t index = kPrefixSize + capacity_; index < storage_.size(); ++index)
        {
            if (storage_[index] != kCanary)
            {
                return false;
            }
        }
        return true;
    }

    bool IsUnaligned() const
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): find the guarded payload address.
        const std::uint8_t* const payload = storage_.data() + kPrefixSize;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): inspect the byte address alignment.
        return (reinterpret_cast<std::uintptr_t>(payload) % alignof(std::uint32_t)) != 0U;
    }

    void FlipByte(std::size_t index)
    {
        if (index < capacity_)
        {
            storage_[kPrefixSize + index] ^= 0x01U;
        }
    }

  private:
    static constexpr std::size_t kPrefixSize = 17U;
    static constexpr std::size_t kSuffixSize = 17U;
    static constexpr std::uint8_t kCanary = 0xD3U;

    std::size_t capacity_;
    std::vector<std::uint8_t> storage_;
};

template <typename Operation, typename... Args>
bool OperationSucceeded(Operation operation, Args... args)
{
    if constexpr (std::is_void_v<std::invoke_result_t<Operation, Args...>>)
    {
        operation(args...);
        return true;
    }
    else
    {
        return operation(args...) == ERR_OK;
    }
}

using SignatureKeyPairOperation = std::function<bool(uint8*, uint8*)>;
using SignatureSignOperation = std::function<bool(uint8*, uint32*, const uint8*, uint32, const uint8*)>;
using SignatureVerifyOperation = std::function<uint8(const uint8*, uint32, const uint8*, uint32, const uint8*)>;

struct SignatureCase
{
    const char* name = "";
    std::size_t public_key_size = 0U;
    std::size_t secret_key_size = 0U;
    std::size_t signature_capacity = 0U;
    SignatureKeyPairOperation keypair;
    SignatureSignOperation sign;
    SignatureVerifyOperation verify;
};

template <auto KeyPair, auto Sign, auto Verify>
SignatureCase MakeSignatureCase(const char* name,
                                std::size_t public_key_size,
                                std::size_t secret_key_size,
                                std::size_t signature_capacity)
{
    return {
        name,
        public_key_size,
        secret_key_size,
        signature_capacity,
        [](uint8* public_key, uint8* secret_key) {
            return OperationSucceeded(KeyPair, public_key, secret_key);
        },
        [](uint8* signature, uint32* signature_len, const uint8* message, uint32 message_len, const uint8* secret_key) {
            return OperationSucceeded(Sign, signature, signature_len, message, message_len, secret_key);
        },
        [](const uint8* signature,
           uint32 signature_len,
           const uint8* message,
           uint32 message_len,
           const uint8* public_key) {
            return Verify(signature, signature_len, message, message_len, public_key);
        }};
}

const std::array<SignatureCase, kDirectSignatureVariantCount>& SignatureCases()
{
    static const std::array<SignatureCase, kDirectSignatureVariantCount> cases = {{
        MakeSignatureCase<FN_DSA_512_Crypto_Sign_KeyPair,
                          FN_DSA_512_Crypto_Sign_Signature,
                          FN_DSA_512_Crypto_Sign_Verify>(
            "FN_DSA_512", FN_DSA_512_CRYPTO_PUBLICKEYBYTES, FN_DSA_512_CRYPTO_SECRETKEYBYTES, FN_DSA_512_CRYPTO_BYTES),
        MakeSignatureCase<FN_DSA_1024_Crypto_Sign_KeyPair,
                          FN_DSA_1024_Crypto_Sign_Signature,
                          FN_DSA_1024_Crypto_Sign_Verify>("FN_DSA_1024",
                                                          FN_DSA_1024_CRYPTO_PUBLICKEYBYTES,
                                                          FN_DSA_1024_CRYPTO_SECRETKEYBYTES,
                                                          FN_DSA_1024_CRYPTO_BYTES),
        MakeSignatureCase<SLH_DSA_SHA2_128fSimple_Crypto_Sign_KeyPair,
                          SLH_DSA_SHA2_128fSimple_Crypto_Sign_Signature,
                          SLH_DSA_SHA2_128fSimple_Crypto_Sign_Verify>("SLH_DSA_SHA2_128f",
                                                                      SLH_DSA_SHA2_128FSIMPLE_PK_BYTES,
                                                                      SLH_DSA_SHA2_128FSIMPLE_SK_BYTES,
                                                                      SLH_DSA_SHA2_128FSIMPLE_BYTES),
        MakeSignatureCase<SLH_DSA_SHA2_128sSimple_Crypto_Sign_KeyPair,
                          SLH_DSA_SHA2_128sSimple_Crypto_Sign_Signature,
                          SLH_DSA_SHA2_128sSimple_Crypto_Sign_Verify>("SLH_DSA_SHA2_128s",
                                                                      SLH_DSA_SHA2_128SSIMPLE_PK_BYTES,
                                                                      SLH_DSA_SHA2_128SSIMPLE_SK_BYTES,
                                                                      SLH_DSA_SHA2_128SSIMPLE_BYTES),
        MakeSignatureCase<SLH_DSA_SHA2_192fSimple_Crypto_Sign_KeyPair,
                          SLH_DSA_SHA2_192fSimple_Crypto_Sign_Signature,
                          SLH_DSA_SHA2_192fSimple_Crypto_Sign_Verify>("SLH_DSA_SHA2_192f",
                                                                      SLH_DSA_SHA2_192FSIMPLE_PK_BYTES,
                                                                      SLH_DSA_SHA2_192FSIMPLE_SK_BYTES,
                                                                      SLH_DSA_SHA2_192FSIMPLE_BYTES),
        MakeSignatureCase<SLH_DSA_SHA2_192sSimple_Crypto_Sign_KeyPair,
                          SLH_DSA_SHA2_192sSimple_Crypto_Sign_Signature,
                          SLH_DSA_SHA2_192sSimple_Crypto_Sign_Verify>("SLH_DSA_SHA2_192s",
                                                                      SLH_DSA_SHA2_192SSIMPLE_PK_BYTES,
                                                                      SLH_DSA_SHA2_192SSIMPLE_SK_BYTES,
                                                                      SLH_DSA_SHA2_192SSIMPLE_BYTES),
        MakeSignatureCase<SLH_DSA_SHA2_256fSimple_Crypto_Sign_KeyPair,
                          SLH_DSA_SHA2_256fSimple_Crypto_Sign_Signature,
                          SLH_DSA_SHA2_256fSimple_Crypto_Sign_Verify>("SLH_DSA_SHA2_256f",
                                                                      SLH_DSA_SHA2_256FSIMPLE_PK_BYTES,
                                                                      SLH_DSA_SHA2_256FSIMPLE_SK_BYTES,
                                                                      SLH_DSA_SHA2_256FSIMPLE_BYTES),
        MakeSignatureCase<SLH_DSA_SHA2_256sSimple_Crypto_Sign_KeyPair,
                          SLH_DSA_SHA2_256sSimple_Crypto_Sign_Signature,
                          SLH_DSA_SHA2_256sSimple_Crypto_Sign_Verify>("SLH_DSA_SHA2_256s",
                                                                      SLH_DSA_SHA2_256SSIMPLE_PK_BYTES,
                                                                      SLH_DSA_SHA2_256SSIMPLE_SK_BYTES,
                                                                      SLH_DSA_SHA2_256SSIMPLE_BYTES),
        MakeSignatureCase<SLH_DSA_SHAKE_128fSimple_Crypto_Sign_KeyPair,
                          SLH_DSA_SHAKE_128fSimple_Crypto_Sign_Signature,
                          SLH_DSA_SHAKE_128fSimple_Crypto_Sign_Verify>("SLH_DSA_SHAKE_128f",
                                                                       SLH_DSA_SHAKE_128FSIMPLE_PK_BYTES,
                                                                       SLH_DSA_SHAKE_128FSIMPLE_SK_BYTES,
                                                                       SLH_DSA_SHAKE_128FSIMPLE_BYTES),
        MakeSignatureCase<SLH_DSA_SHAKE_128sSimple_Crypto_Sign_KeyPair,
                          SLH_DSA_SHAKE_128sSimple_Crypto_Sign_Signature,
                          SLH_DSA_SHAKE_128sSimple_Crypto_Sign_Verify>("SLH_DSA_SHAKE_128s",
                                                                       SLH_DSA_SHAKE_128SSIMPLE_PK_BYTES,
                                                                       SLH_DSA_SHAKE_128SSIMPLE_SK_BYTES,
                                                                       SLH_DSA_SHAKE_128SSIMPLE_BYTES),
        MakeSignatureCase<SLH_DSA_SHAKE_192fSimple_Crypto_Sign_KeyPair,
                          SLH_DSA_SHAKE_192fSimple_Crypto_Sign_Signature,
                          SLH_DSA_SHAKE_192fSimple_Crypto_Sign_Verify>("SLH_DSA_SHAKE_192f",
                                                                       SLH_DSA_SHAKE_192FSIMPLE_PK_BYTES,
                                                                       SLH_DSA_SHAKE_192FSIMPLE_SK_BYTES,
                                                                       SLH_DSA_SHAKE_192FSIMPLE_BYTES),
        MakeSignatureCase<SLH_DSA_SHAKE_192sSimple_Crypto_Sign_KeyPair,
                          SLH_DSA_SHAKE_192sSimple_Crypto_Sign_Signature,
                          SLH_DSA_SHAKE_192sSimple_Crypto_Sign_Verify>("SLH_DSA_SHAKE_192s",
                                                                       SLH_DSA_SHAKE_192SSIMPLE_PK_BYTES,
                                                                       SLH_DSA_SHAKE_192SSIMPLE_SK_BYTES,
                                                                       SLH_DSA_SHAKE_192SSIMPLE_BYTES),
        MakeSignatureCase<SLH_DSA_SHAKE_256fSimple_Crypto_Sign_KeyPair,
                          SLH_DSA_SHAKE_256fSimple_Crypto_Sign_Signature,
                          SLH_DSA_SHAKE_256fSimple_Crypto_Sign_Verify>("SLH_DSA_SHAKE_256f",
                                                                       SLH_DSA_SHAKE_256FSIMPLE_PK_BYTES,
                                                                       SLH_DSA_SHAKE_256FSIMPLE_SK_BYTES,
                                                                       SLH_DSA_SHAKE_256FSIMPLE_BYTES),
        MakeSignatureCase<SLH_DSA_SHAKE_256sSimple_Crypto_Sign_KeyPair,
                          SLH_DSA_SHAKE_256sSimple_Crypto_Sign_Signature,
                          SLH_DSA_SHAKE_256sSimple_Crypto_Sign_Verify>("SLH_DSA_SHAKE_256s",
                                                                       SLH_DSA_SHAKE_256SSIMPLE_PK_BYTES,
                                                                       SLH_DSA_SHAKE_256SSIMPLE_SK_BYTES,
                                                                       SLH_DSA_SHAKE_256SSIMPLE_BYTES),
    }};
    return cases;
}

class DirectSignatureFunctionalTest : public ::testing::TestWithParam<SignatureCase>
{
  protected:
    void SetUp() override
    {
        ASSERT_EQ(RegisterTestRandomBytesProvider(), IavStatusOk);
    }
};

// NOLINTNEXTLINE(readability-function-cognitive-complexity): the assertions document each buffer and operation
// contract.
TEST_P(DirectSignatureFunctionalTest, RoundTripsAndRejectsTamperedSignatureWithGuardedUnalignedBuffers)
{
    static constexpr std::array<std::uint8_t, 15U> kMessage = {
        0x49U, 0x41U, 0x56U, 0x2DU, 0x50U, 0x72U, 0x69U, 0x6DU, 0x75U, 0x6CU, 0x61U, 0x2DU, 0x54U, 0x65U, 0x73U};
    const SignatureCase& test_case = GetParam();
    GuardedBuffer public_key(test_case.public_key_size);
    GuardedBuffer secret_key(test_case.secret_key_size);
    GuardedBuffer message(kMessage.size());
    GuardedBuffer signature(test_case.signature_capacity);
    std::copy(kMessage.begin(), kMessage.end(), message.data());

    ASSERT_TRUE(public_key.IsUnaligned());
    ASSERT_TRUE(secret_key.IsUnaligned());
    ASSERT_TRUE(message.IsUnaligned());
    ASSERT_TRUE(signature.IsUnaligned());
    ASSERT_TRUE(test_case.keypair(public_key.data(), secret_key.data()));

    uint32 signature_len = 0U;
    ASSERT_TRUE(test_case.sign(
        signature.data(), &signature_len, message.data(), static_cast<uint32>(kMessage.size()), secret_key.data()));
    ASSERT_GT(signature_len, 0U);
    ASSERT_LE(static_cast<std::size_t>(signature_len), test_case.signature_capacity);
    ASSERT_EQ(
        test_case.verify(
            signature.data(), signature_len, message.data(), static_cast<uint32>(kMessage.size()), public_key.data()),
        ERR_OK);

    signature.FlipByte(static_cast<std::size_t>(signature_len) / 2U);
    EXPECT_NE(
        test_case.verify(
            signature.data(), signature_len, message.data(), static_cast<uint32>(kMessage.size()), public_key.data()),
        ERR_OK);

    EXPECT_TRUE(public_key.CanariesIntact());
    EXPECT_TRUE(secret_key.CanariesIntact());
    EXPECT_TRUE(message.CanariesIntact());
    EXPECT_TRUE(signature.CanariesIntact());
}

std::string SignatureTestName(const ::testing::TestParamInfo<SignatureCase>& info)
{
    return info.param.name;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables, readability-identifier-length): generated by
// gtest.
INSTANTIATE_TEST_SUITE_P(AllDirectSignatureVariants,
                         DirectSignatureFunctionalTest,
                         ::testing::ValuesIn(SignatureCases()),
                         SignatureTestName);

using KemKeyPairOperation = std::function<sint8(uint8*, uint8*)>;
using KemEncapsulateOperation = std::function<sint8(uint8*, uint8*, const uint8*)>;
using KemDecapsulateOperation = std::function<sint8(uint8*, const uint8*, const uint8*)>;

struct KemCase
{
    const char* name = "";
    std::size_t public_key_size = 0U;
    std::size_t secret_key_size = 0U;
    std::size_t ciphertext_size = 0U;
    KemKeyPairOperation keypair;
    KemEncapsulateOperation encapsulate;
    KemDecapsulateOperation decapsulate;
};

const std::array<KemCase, kDirectKemVariantCount>& KemCases()
{
    static const std::array<KemCase, kDirectKemVariantCount> cases = {{
        {"HQC128",
         HQC128_CRYPTO_PUBLICKEYBYTES,
         HQC128_CRYPTO_SECRETKEYBYTES,
         HQC128_CRYPTO_CIPHERTEXTBYTES,
         Hqc128_Crypto_Kem_KeyPair,
         Hqc128_Crypto_Kem_Enc,
         Hqc128_Crypto_Kem_Dec},
        {"HQC192",
         HQC192_CRYPTO_PUBLICKEYBYTES,
         HQC192_CRYPTO_SECRETKEYBYTES,
         HQC192_CRYPTO_CIPHERTEXTBYTES,
         Hqc192_Crypto_Kem_KeyPair,
         Hqc192_Crypto_Kem_Enc,
         Hqc192_Crypto_Kem_Dec},
        {"HQC256",
         HQC256_CRYPTO_PUBLICKEYBYTES,
         HQC256_CRYPTO_SECRETKEYBYTES,
         HQC256_CRYPTO_CIPHERTEXTBYTES,
         Hqc256_Crypto_Kem_KeyPair,
         Hqc256_Crypto_Kem_Enc,
         Hqc256_Crypto_Kem_Dec},
    }};
    return cases;
}

class DirectKemFunctionalTest : public ::testing::TestWithParam<KemCase>
{
  protected:
    void SetUp() override
    {
        ASSERT_EQ(RegisterTestRandomBytesProvider(), IavStatusOk);
    }
};

// NOLINTNEXTLINE(readability-function-cognitive-complexity): the assertions document each buffer and operation
// contract.
TEST_P(DirectKemFunctionalTest, RoundTripsAndRejectsTamperedCiphertextWithGuardedUnalignedBuffers)
{
    const KemCase& test_case = GetParam();
    GuardedBuffer public_key(test_case.public_key_size);
    GuardedBuffer secret_key(test_case.secret_key_size);
    GuardedBuffer ciphertext(test_case.ciphertext_size);
    GuardedBuffer encapsulated_secret(HQC_SSBYTES);
    GuardedBuffer decapsulated_secret(HQC_SSBYTES);
    GuardedBuffer rejected_secret(HQC_SSBYTES);

    ASSERT_TRUE(public_key.IsUnaligned());
    ASSERT_TRUE(secret_key.IsUnaligned());
    ASSERT_TRUE(ciphertext.IsUnaligned());
    ASSERT_TRUE(encapsulated_secret.IsUnaligned());
    ASSERT_TRUE(decapsulated_secret.IsUnaligned());
    ASSERT_TRUE(rejected_secret.IsUnaligned());
    ASSERT_EQ(test_case.keypair(public_key.data(), secret_key.data()), 0);
    ASSERT_EQ(test_case.encapsulate(ciphertext.data(), encapsulated_secret.data(), public_key.data()), 0);
    ASSERT_EQ(test_case.decapsulate(decapsulated_secret.data(), ciphertext.data(), secret_key.data()), 0);
    ASSERT_EQ(std::memcmp(encapsulated_secret.data(), decapsulated_secret.data(), HQC_SSBYTES), 0);

    ciphertext.FlipByte(0U);
    EXPECT_EQ(test_case.decapsulate(rejected_secret.data(), ciphertext.data(), secret_key.data()), -1);

    EXPECT_TRUE(public_key.CanariesIntact());
    EXPECT_TRUE(secret_key.CanariesIntact());
    EXPECT_TRUE(ciphertext.CanariesIntact());
    EXPECT_TRUE(encapsulated_secret.CanariesIntact());
    EXPECT_TRUE(decapsulated_secret.CanariesIntact());
    EXPECT_TRUE(rejected_secret.CanariesIntact());
}

std::string KemTestName(const ::testing::TestParamInfo<KemCase>& info)
{
    return info.param.name;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables, readability-identifier-length): generated by
// gtest.
INSTANTIATE_TEST_SUITE_P(AllDirectHqcVariants, DirectKemFunctionalTest, ::testing::ValuesIn(KemCases()), KemTestName);

}  // namespace
