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

/// @file fn_dsa_malformed_header_test.cpp
/// @brief Malformed FN-DSA detached-signature and attached-message header tests.

#include "score/iav_primula/include/iav_primula_ffi.h"

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include "FN_DSA_1024_api.h"
#include "FN_DSA_512_api.h"
#include "FsmSw_CommonLib.h"
#include "score/iav_primula/include/Platform_Types.h"
}

namespace
{

constexpr std::size_t kFnDsaNonceSize = 40U;
constexpr std::size_t kAttachedMessageFixedPrefix = 2U + kFnDsaNonceSize;
constexpr std::size_t kMinimumAttachedObjectSize = kAttachedMessageFixedPrefix + 1U;
constexpr std::size_t kMessageSize = 19U;
constexpr std::uint32_t kErrNotOk = ERR_NOT_OK;
constexpr std::uint8_t kFailureOutputFill = 0xA5U;
constexpr unsigned int kLengthHighByteShift = 8U;

constexpr std::array<std::uint8_t, kMessageSize> kMessage = {0x46U,
                                                             0x4EU,
                                                             0x2DU,
                                                             0x44U,
                                                             0x53U,
                                                             0x41U,
                                                             0x2DU,
                                                             0x6DU,
                                                             0x61U,
                                                             0x6FU,
                                                             0x6CU,
                                                             0x66U,
                                                             0x6FU,
                                                             0x72U,
                                                             0x6DU,
                                                             0x65U,
                                                             0x64U,
                                                             0x2DU,
                                                             0x68U};

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
using AttachedSignOperation = uint8 (*)(uint8*, uint32*, const uint8*, uint32, const uint8*);
using AttachedOpenOperation = uint8 (*)(uint8*, uint32*, const uint8*, uint32, const uint8*);

struct FnDsaCase
{
    const char* name = "";
    std::size_t public_key_size = 0U;
    std::size_t secret_key_size = 0U;
    std::size_t signature_size = 0U;
    KeyPairOperation keypair = nullptr;
    DetachedSignOperation detached_sign = nullptr;
    DetachedVerifyOperation detached_verify = nullptr;
    AttachedSignOperation attached_sign = nullptr;
    AttachedOpenOperation attached_open = nullptr;
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
         FN_DSA_512_Crypto_Sign_Verify,
         FN_DSA_512_Crypto_Sign,
         FN_DSA_512_Crypto_Sign_Open},
        {"FN_DSA_1024",
         FN_DSA_1024_CRYPTO_PUBLICKEYBYTES,
         FN_DSA_1024_CRYPTO_SECRETKEYBYTES,
         FN_DSA_1024_CRYPTO_BYTES,
         FN_DSA_1024_Crypto_Sign_KeyPair,
         FN_DSA_1024_Crypto_Sign_Signature,
         FN_DSA_1024_Crypto_Sign_Verify,
         FN_DSA_1024_Crypto_Sign,
         FN_DSA_1024_Crypto_Sign_Open},
    }};
    return cases;
}

struct TestKeyPair
{
    std::vector<std::uint8_t> public_key;
    std::vector<std::uint8_t> secret_key;
};

bool GenerateTestKeyPair(const FnDsaCase& test_case, TestKeyPair* key_pair)
{
    key_pair->public_key.resize(test_case.public_key_size);
    key_pair->secret_key.resize(test_case.secret_key_size);
    return test_case.keypair(key_pair->public_key.data(), key_pair->secret_key.data()) == ERR_OK;
}

bool CreateValidAttachedMessage(const FnDsaCase& test_case,
                                const TestKeyPair& key_pair,
                                std::vector<std::uint8_t>* signed_message,
                                uint32* signed_message_len)
{
    signed_message->resize(test_case.signature_size + kMessage.size());
    *signed_message_len = 0U;
    const uint8 status = test_case.attached_sign(signed_message->data(),
                                                 signed_message_len,
                                                 kMessage.data(),
                                                 static_cast<uint32>(kMessage.size()),
                                                 key_pair.secret_key.data());
    return (status == ERR_OK) && (*signed_message_len <= signed_message->size());
}

class FnDsaMalformedHeaderTest : public ::testing::TestWithParam<FnDsaCase>
{
  protected:
    void SetUp() override
    {
        ASSERT_EQ(RegisterTestRandomBytesProvider(), IavStatusOk);
    }
};

// M04 safety gate: FN-DSA's detached verifier must reject a logical signature
// shorter than its nonce/header prefix before subtracting those lengths. Use a
// genuine signature in a full-capacity backing array, then pass zero and
// one-byte-short logical lengths; assert only the documented error status.
TEST_P(FnDsaMalformedHeaderTest, RejectsDetachedSignaturesShorterThanNonceHeader)
{
    const FnDsaCase& test_case = GetParam();
    TestKeyPair key_pair;
    ASSERT_TRUE(GenerateTestKeyPair(test_case, &key_pair));

    std::vector<std::uint8_t> signature(test_case.signature_size);
    uint32 signature_len = 0U;
    ASSERT_EQ(test_case.detached_sign(signature.data(),
                                      &signature_len,
                                      kMessage.data(),
                                      static_cast<uint32>(kMessage.size()),
                                      key_pair.secret_key.data()),
              ERR_OK);
    ASSERT_GT(signature_len, 0U);
    ASSERT_LE(static_cast<std::size_t>(signature_len), signature.size());

    static constexpr std::array<uint32, 2U> kShortLogicalLengths = {0U, kFnDsaNonceSize};
    for (const uint32 logical_length : kShortLogicalLengths)
    {
        EXPECT_EQ(test_case.detached_verify(signature.data(),
                                            logical_length,
                                            kMessage.data(),
                                            static_cast<uint32>(kMessage.size()),
                                            key_pair.public_key.data()),
                  kErrNotOk)
            << "logical signature length=" << logical_length;
    }
}

// M04 safety gate: test the repaired Crypto_Sign_Open length guard using
// correctly allocated input/output storage. Test logical lengths 0, 1, and
// 42 against a 42-byte backing array: the implementation reads the first two
// header bytes even for short logical objects, so backing storage must retain
// those bytes. All lengths are below the minimum 43-byte prefix. Output
// mutation is intentionally not asserted because failure contents are not
// specified.
TEST_P(FnDsaMalformedHeaderTest, RejectsSignedMessageShorterThanMinimumPrefix)
{
    const FnDsaCase& test_case = GetParam();
    std::vector<std::uint8_t> malformed_object(kMinimumAttachedObjectSize - 1U, 0U);
    std::vector<std::uint8_t> output(test_case.signature_size + kMessage.size(), kFailureOutputFill);
    std::vector<std::uint8_t> public_key(test_case.public_key_size, 0U);
    static constexpr std::array<uint32, 3U> kShortLogicalLengths = {0U, 1U, 42U};
    for (const uint32 logical_length : kShortLogicalLengths)
    {
        uint32 recovered_len = 0U;
        EXPECT_EQ(test_case.attached_open(
                      output.data(), &recovered_len, malformed_object.data(), logical_length, public_key.data()),
                  kErrNotOk)
            << "logical signed-message length=" << logical_length;
    }
}

// M04 safety gate: malformed embedded lengths previously allowed unsigned
// subtraction before the wrapper settled on its error path. Start from a valid
// attached message and mutate only its two-byte length or embedded logn marker.
// Both buffers remain full-capacity; assert rejection status only, not failure
// output contents.
TEST_P(FnDsaMalformedHeaderTest, RejectsMalformedEmbeddedLengthAndParameterMarker)
{
    const FnDsaCase& test_case = GetParam();
    TestKeyPair key_pair;
    ASSERT_TRUE(GenerateTestKeyPair(test_case, &key_pair));

    std::vector<std::uint8_t> valid_signed_message;
    uint32 valid_signed_message_len = 0U;
    ASSERT_TRUE(CreateValidAttachedMessage(test_case, key_pair, &valid_signed_message, &valid_signed_message_len));

    const uint32 one_past_available_length = valid_signed_message_len - static_cast<uint32>(kFnDsaNonceSize) - 1U;
    const std::array<std::uint16_t, 4U> malformed_lengths = {
        0U, 1U, static_cast<std::uint16_t>(one_past_available_length), UINT16_MAX};
    std::vector<std::uint8_t> output(test_case.signature_size + kMessage.size(), kFailureOutputFill);

    for (const std::uint16_t malformed_length : malformed_lengths)
    {
        std::vector<std::uint8_t> malformed_message = valid_signed_message;
        malformed_message[0U] = static_cast<std::uint8_t>(malformed_length >> kLengthHighByteShift);
        malformed_message[1U] = static_cast<std::uint8_t>(malformed_length);
        uint32 recovered_len = UINT32_MAX;
        EXPECT_EQ(test_case.attached_open(output.data(),
                                          &recovered_len,
                                          malformed_message.data(),
                                          valid_signed_message_len,
                                          key_pair.public_key.data()),
                  kErrNotOk)
            << "embedded signature length=" << malformed_length;
    }

    std::vector<std::uint8_t> wrong_parameter_marker = valid_signed_message;
    const std::size_t marker_offset = kAttachedMessageFixedPrefix + kMessage.size();
    wrong_parameter_marker[marker_offset] ^= 0x01U;
    uint32 recovered_len = UINT32_MAX;
    EXPECT_EQ(test_case.attached_open(output.data(),
                                      &recovered_len,
                                      wrong_parameter_marker.data(),
                                      valid_signed_message_len,
                                      key_pair.public_key.data()),
              kErrNotOk);
}

std::string FnDsaTestName(const ::testing::TestParamInfo<FnDsaCase>& info)
{
    return info.param.name;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables, readability-identifier-length): generated by
// gtest.
INSTANTIATE_TEST_SUITE_P(BothFnDsaParameterSets,
                         FnDsaMalformedHeaderTest,
                         ::testing::ValuesIn(FnDsaCases()),
                         FnDsaTestName);

}  // namespace
