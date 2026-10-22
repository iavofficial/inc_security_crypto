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

/// @file FN_DSA_malformedEncoding_test.cpp
/// @brief Rejects malformed FN-DSA public keys, secret keys, and signatures.

#include "score/iav_primula/include/iav_primula_ffi.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" {
#include "FN_DSA_1024_api.h"
#include "FN_DSA_512_api.h"
#include "FsmSw_CommonLib.h"
#include "score/iav_primula/include/Platform_Types.h"
}

namespace
{

constexpr std::uint32_t kErrNotOk = ERR_NOT_OK;
constexpr std::size_t kNonceAndHeaderSize = 41U;
constexpr std::array<std::uint8_t, 17U> kMessage = {0x46U,
                                                    0x4EU,
                                                    0x2DU,
                                                    0x44U,
                                                    0x53U,
                                                    0x41U,
                                                    0x2DU,
                                                    0x6Du,
                                                    0x61U,
                                                    0x6FU,
                                                    0x6CU,
                                                    0x64U,
                                                    0x2DU,
                                                    0x65U,
                                                    0x6EU,
                                                    0x63U,
                                                    0x2DU};

struct TestRngContext
{
    std::atomic<std::uint64_t> request_counter{0U};
};

int FillTestRandomBytes(std::uint8_t* output, std::size_t output_len, void* user_data)
{
    auto* const context = static_cast<TestRngContext*>(user_data);
    if (context == nullptr || (output == nullptr && output_len != 0U))
    {
        return 1;
    }

    constexpr std::uint64_t kGamma = 0x9E3779B97F4A7C15ULL;
    constexpr std::uint64_t kMultiplier1 = 0xBF58476D1CE4E5B9ULL;
    constexpr std::uint64_t kMultiplier2 = 0x94D049BB133111EBULL;
    constexpr unsigned int kShift1 = 30U;
    constexpr unsigned int kShift2 = 27U;
    constexpr unsigned int kShift3 = 31U;
    constexpr unsigned int kOutputByteShift = 56U;
    const std::uint64_t request = context->request_counter.fetch_add(1U, std::memory_order_relaxed);

    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic): fill the callback's caller-provided byte span.
    for (std::size_t index = 0U; index < output_len; ++index)
    {
        std::uint64_t value = request + kGamma * (index + 1U);
        value = (value ^ (value >> kShift1)) * kMultiplier1;
        value = (value ^ (value >> kShift2)) * kMultiplier2;
        value ^= value >> kShift3;
        output[index] = static_cast<std::uint8_t>(value >> kOutputByteShift);
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return 0;
}

iav_status RegisterTestRandomBytesProvider()
{
    static TestRngContext context;
    static const iav_status status = iav_random_bytes_provider_register(FillTestRandomBytes, &context);
    return status;
}

using KeyPairOperation = uint8 (*)(uint8*, uint8*);
using DetachedSignOperation = uint8 (*)(uint8*, uint32*, const uint8*, uint32, const uint8*);
using DetachedVerifyOperation = uint8 (*)(const uint8*, uint32, const uint8*, uint32, const uint8*);

struct FnDsaCase
{
    const char* name = "";
    std::size_t public_key_size = 0U;
    std::size_t secret_key_size = 0U;
    std::size_t signature_size = 0U;
    KeyPairOperation keypair = nullptr;
    DetachedSignOperation detached_sign = nullptr;
    DetachedVerifyOperation detached_verify = nullptr;
};

const std::array<FnDsaCase, 2U>& FnDsaCases()
{
    static const std::array<FnDsaCase, 2U> cases = {{
        {"FN_DSA_512",
         FN_DSA_512_CRYPTO_PUBLICKEYBYTES,
         FN_DSA_512_CRYPTO_SECRETKEYBYTES,
         FN_DSA_512_CRYPTO_BYTES,
         FN_DSA_512_Crypto_Sign_KeyPair,
         FN_DSA_512_Crypto_Sign_Signature,
         FN_DSA_512_Crypto_Sign_Verify},
        {"FN_DSA_1024",
         FN_DSA_1024_CRYPTO_PUBLICKEYBYTES,
         FN_DSA_1024_CRYPTO_SECRETKEYBYTES,
         FN_DSA_1024_CRYPTO_BYTES,
         FN_DSA_1024_Crypto_Sign_KeyPair,
         FN_DSA_1024_Crypto_Sign_Signature,
         FN_DSA_1024_Crypto_Sign_Verify},
    }};
    return cases;
}

class FnDsaMalformedEncodingTest : public ::testing::TestWithParam<FnDsaCase>
{
  protected:
    void SetUp() override
    {
        ASSERT_EQ(RegisterTestRandomBytesProvider(), IavStatusOk);
    }
};

// M04 P2 FN-DSA API gap: reject invalid public-key tags/residues, forbidden
// secret-key trim values, malformed compressed signature data, and a wrong
// detached-signature tag. Keep all objects fully allocated and assert status
// only; short logical signature lengths are covered by M06.1.
TEST_P(FnDsaMalformedEncodingTest, RejectsMalformedKeyAndSignatureEncodings)
{
    const FnDsaCase& test_case = GetParam();
    std::vector<std::uint8_t> public_key(test_case.public_key_size);
    std::vector<std::uint8_t> secret_key(test_case.secret_key_size);
    ASSERT_EQ(ERR_OK, test_case.keypair(public_key.data(), secret_key.data()));

    std::vector<std::uint8_t> signature(test_case.signature_size);
    uint32 signature_len = 0U;
    ASSERT_EQ(ERR_OK,
              test_case.detached_sign(signature.data(),
                                      &signature_len,
                                      kMessage.data(),
                                      static_cast<uint32>(kMessage.size()),
                                      secret_key.data()));
    ASSERT_GT(signature_len, kNonceAndHeaderSize);
    ASSERT_EQ(
        ERR_OK,
        test_case.detached_verify(
            signature.data(), signature_len, kMessage.data(), static_cast<uint32>(kMessage.size()), public_key.data()));

    std::vector<std::uint8_t> malformed_public_key = public_key;
    malformed_public_key[0U] ^= 1U;
    EXPECT_EQ(test_case.detached_verify(signature.data(),
                                        signature_len,
                                        kMessage.data(),
                                        static_cast<uint32>(kMessage.size()),
                                        malformed_public_key.data()),
              kErrNotOk);

    // The first packed modq value is 0x3001 (12289), one above the valid range.
    malformed_public_key = public_key;
    malformed_public_key[1U] = 0xC0U;
    malformed_public_key[2U] = 0x04U;
    EXPECT_EQ(test_case.detached_verify(signature.data(),
                                        signature_len,
                                        kMessage.data(),
                                        static_cast<uint32>(kMessage.size()),
                                        malformed_public_key.data()),
              kErrNotOk);

    // The first trim coefficient is the forbidden -2^(bits-1) for both sets.
    std::vector<std::uint8_t> malformed_secret_key = secret_key;
    malformed_secret_key[1U] = 0x80U;
    std::vector<std::uint8_t> rejected_signature(test_case.signature_size);
    uint32 rejected_signature_len = 0U;
    EXPECT_EQ(test_case.detached_sign(rejected_signature.data(),
                                      &rejected_signature_len,
                                      kMessage.data(),
                                      static_cast<uint32>(kMessage.size()),
                                      malformed_secret_key.data()),
              kErrNotOk);

    std::vector<std::uint8_t> malformed_signature = signature;
    malformed_signature[0U] ^= 1U;
    EXPECT_EQ(test_case.detached_verify(malformed_signature.data(),
                                        signature_len,
                                        kMessage.data(),
                                        static_cast<uint32>(kMessage.size()),
                                        public_key.data()),
              kErrNotOk);

    malformed_signature = signature;
    std::fill(malformed_signature.begin() + static_cast<std::ptrdiff_t>(kNonceAndHeaderSize),
              malformed_signature.begin() + static_cast<std::ptrdiff_t>(signature_len),
              0U);
    EXPECT_EQ(test_case.detached_verify(malformed_signature.data(),
                                        signature_len,
                                        kMessage.data(),
                                        static_cast<uint32>(kMessage.size()),
                                        public_key.data()),
              kErrNotOk);
}

INSTANTIATE_TEST_SUITE_P(AllSupportedParameterSets,
                         FnDsaMalformedEncodingTest,
                         ::testing::ValuesIn(FnDsaCases()),
                         [](const ::testing::TestParamInfo<FnDsaCase>& info) {
                             return info.param.name;
                         });

}  // namespace
