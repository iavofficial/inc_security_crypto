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

/// @file fn_dsa_attached_message_test.cpp
/// @brief Valid attached-message sign/open tests for the FN-DSA public APIs.

#include "score/iav_primula/tests/common/coverage_test_support.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include "FN_DSA_1024_api.h"
#include "FN_DSA_512_api.h"
#include "FsmSw_CommonLib.h"
#include "score/iav_primula/include/Platform_Types.h"
}
#include "score/iav_primula/include/iav_primula_ffi.h"

namespace
{

constexpr std::size_t kFnDsaNonceSize = 40U;

using KeyPairOperation = uint8 (*)(uint8*, uint8*);
using AttachedSignOperation = uint8 (*)(uint8*, uint32*, const uint8*, uint32, const uint8*);
using AttachedOpenOperation = uint8 (*)(uint8*, uint32*, const uint8*, uint32, const uint8*);

struct FnDsaCase
{
    const char* name = "";
    std::size_t public_key_size = 0U;
    std::size_t secret_key_size = 0U;
    std::size_t signature_capacity = 0U;
    std::uint8_t signature_header = 0U;
    KeyPairOperation keypair = nullptr;
    AttachedSignOperation sign = nullptr;
    AttachedOpenOperation open = nullptr;
};

const std::array<FnDsaCase, 2U>& FnDsaCases()
{
    static const std::array<FnDsaCase, 2U> cases = {{
        {"FN_DSA_512",
         FN_DSA_512_CRYPTO_PUBLICKEYBYTES,
         FN_DSA_512_CRYPTO_SECRETKEYBYTES,
         FN_DSA_512_CRYPTO_BYTES,
         0x29U,
         FN_DSA_512_Crypto_Sign_KeyPair,
         FN_DSA_512_Crypto_Sign,
         FN_DSA_512_Crypto_Sign_Open},
        {"FN_DSA_1024",
         FN_DSA_1024_CRYPTO_PUBLICKEYBYTES,
         FN_DSA_1024_CRYPTO_SECRETKEYBYTES,
         FN_DSA_1024_CRYPTO_BYTES,
         0x2AU,
         FN_DSA_1024_Crypto_Sign_KeyPair,
         FN_DSA_1024_Crypto_Sign,
         FN_DSA_1024_Crypto_Sign_Open},
    }};
    return cases;
}

class FnDsaAttachedMessageTest : public ::testing::TestWithParam<FnDsaCase>
{
  protected:
    void SetUp() override
    {
        ASSERT_EQ(iav_primula_test::RegisterDeterministicRandomProvider(), IavStatusOk);
    }
};

// NOLINTBEGIN(readability-function-cognitive-complexity): detailed assertions
// cover several API contracts in one parameterized happy-path test.
// M04 P1: FN-DSA attached Crypto_Sign/Crypto_Sign_Open paths are not exercised by
// the detached-sign tests. Exercise valid empty and non-empty messages for both
// parameter sets, validate the embedded length and logn header, and check the
// documented arbitrary message/output overlap using full-capacity buffers.
// Malformed length/header cases remain excluded until the separate safety gate
// is resolved.
TEST_P(FnDsaAttachedMessageTest, SignsOpensAndSupportsMessageOverlapForValidInputs)
{
    static constexpr std::array<std::uint8_t, 19U> kMessage = {0x46U,
                                                               0x4EU,
                                                               0x2DU,
                                                               0x44U,
                                                               0x53U,
                                                               0x41U,
                                                               0x2DU,
                                                               0x61U,
                                                               0x74U,
                                                               0x74U,
                                                               0x61U,
                                                               0x63U,
                                                               0x68U,
                                                               0x65U,
                                                               0x64U,
                                                               0x2DU,
                                                               0x74U,
                                                               0x65U,
                                                               0x73U};
    static constexpr std::array<std::uint8_t, 1U> kEmptyMessage = {0U};
    const FnDsaCase& test_case = GetParam();
    std::vector<std::uint8_t> public_key(test_case.public_key_size);
    std::vector<std::uint8_t> secret_key(test_case.secret_key_size);
    ASSERT_EQ(test_case.keypair(public_key.data(), secret_key.data()), ERR_OK);

    const std::array<std::pair<const std::uint8_t*, std::size_t>, 2U> messages = {{
        {kEmptyMessage.data(), 0U},
        {kMessage.data(), kMessage.size()},
    }};
    for (const auto& message : messages)
    {
        std::vector<std::uint8_t> signed_message(test_case.signature_capacity + message.second);
        uint32 signed_message_len = 0U;
        ASSERT_EQ(test_case.sign(signed_message.data(),
                                 &signed_message_len,
                                 message.first,
                                 static_cast<uint32>(message.second),
                                 secret_key.data()),
                  ERR_OK);
        ASSERT_LE(static_cast<std::size_t>(signed_message_len), signed_message.size());
        ASSERT_GE(static_cast<std::size_t>(signed_message_len), 2U + kFnDsaNonceSize + message.second + 2U);

        const std::size_t embedded_signature_len =
            (static_cast<std::size_t>(signed_message[0U]) << 8U) | signed_message[1U];
        EXPECT_EQ(embedded_signature_len,
                  static_cast<std::size_t>(signed_message_len) - 2U - kFnDsaNonceSize - message.second);
        EXPECT_EQ(signed_message[2U + kFnDsaNonceSize + message.second], test_case.signature_header);

        std::vector<std::uint8_t> recovered(message.second + 1U, 0xA5U);
        uint32 recovered_len = UINT32_MAX;
        ASSERT_EQ(test_case.open(
                      recovered.data(), &recovered_len, signed_message.data(), signed_message_len, public_key.data()),
                  ERR_OK);
        ASSERT_EQ(recovered_len, message.second);
        EXPECT_TRUE(std::equal(message.first, message.first + message.second, recovered.begin()));
    }

    // The FN-DSA contract permits the message input to overlap the signed-message
    // output. Keep secret-key storage disjoint and allocate the documented maximum.
    std::vector<std::uint8_t> in_place(test_case.signature_capacity + kMessage.size(), 0U);
    std::copy(kMessage.begin(), kMessage.end(), in_place.begin());
    uint32 signed_message_len = 0U;
    ASSERT_EQ(test_case.sign(in_place.data(),
                             &signed_message_len,
                             in_place.data(),
                             static_cast<uint32>(kMessage.size()),
                             secret_key.data()),
              ERR_OK);

    uint32 recovered_len = 0U;
    ASSERT_EQ(test_case.open(in_place.data(), &recovered_len, in_place.data(), signed_message_len, public_key.data()),
              ERR_OK);
    EXPECT_EQ(recovered_len, kMessage.size());
    EXPECT_TRUE(std::equal(kMessage.begin(), kMessage.end(), in_place.begin()));
}
// NOLINTEND(readability-function-cognitive-complexity)

std::string FnDsaTestName(const ::testing::TestParamInfo<FnDsaCase>& info)
{
    return info.param.name;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables, readability-identifier-length): generated by
// gtest.
INSTANTIATE_TEST_SUITE_P(BothFnDsaParameterSets,
                         FnDsaAttachedMessageTest,
                         ::testing::ValuesIn(FnDsaCases()),
                         FnDsaTestName);

}  // namespace
