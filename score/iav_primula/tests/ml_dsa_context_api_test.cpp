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

/// @file ml_dsa_context_api_test.cpp
/// @brief Context-aware detached and attached signing tests for ML-DSA.

#include "coverage_test_support.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include "FsmSw_CommonLib.h"
#include "ML_DSA_44_api.h"
#include "ML_DSA_65_api.h"
#include "ML_DSA_87_api.h"
#include "score/iav_primula/include/Platform_Types.h"
}
#include "score/iav_primula/include/iav_primula_ffi.h"

namespace
{

using KeyPairOperation = void (*)(uint8*, uint8*);
using ContextSignOperation = uint8 (*)(uint8*, uint32*, const uint8*, uint32, const uint8*, uint32, const uint8*);
using ContextAttachedSignOperation =
    uint8 (*)(uint8*, uint32*, const uint8*, uint32, const uint8*, uint32, const uint8*);
using ContextVerifyOperation =
    uint8 (*)(const uint8*, uint32, const uint8*, uint32, const uint8*, uint32, const uint8*);
using ContextAttachedOpenOperation =
    uint8 (*)(uint8*, uint32*, const uint8*, uint32, const uint8*, uint32, const uint8*);

struct MlDsaContextCase
{
    const char* name = "";
    std::size_t public_key_size = 0U;
    std::size_t secret_key_size = 0U;
    std::size_t signature_size = 0U;
    KeyPairOperation keypair = nullptr;
    ContextSignOperation sign = nullptr;
    ContextAttachedSignOperation attached_sign = nullptr;
    ContextVerifyOperation verify = nullptr;
    ContextAttachedOpenOperation attached_open = nullptr;
};

const std::array<MlDsaContextCase, 3U>& MlDsaContextCases()
{
    static const std::array<MlDsaContextCase, 3U> cases = {{
        {"ML_DSA_44",
         FSMSW_ML_DSA_44_CRYPTO_PUBLICKEYBYTES,
         FSMSW_ML_DSA_44_CRYPTO_SECRETKEYBYTES,
         FSMSW_ML_DSA_44_CRYPTO_BYTES,
         ML_DSA_44_Crypto_Sign_KeyPair,
         ML_DSA_44_Crypto_Sign_Signature_Ctx,
         ML_DSA_44_Crypto_Sign_Ctx,
         ML_DSA_44_Crypto_Sign_Verify_Ctx,
         ML_DSA_44_Crypto_Sign_Open_Ctx},
        {"ML_DSA_65",
         FSMSW_ML_DSA_65_CRYPTO_PUBLICKEYBYTES,
         FSMSW_ML_DSA_65_CRYPTO_SECRETKEYBYTES,
         FSMSW_ML_DSA_65_CRYPTO_BYTES,
         ML_DSA_65_Crypto_Sign_KeyPair,
         ML_DSA_65_Crypto_Sign_Signature_Ctx,
         ML_DSA_65_Crypto_Sign_Ctx,
         ML_DSA_65_Crypto_Sign_Verify_Ctx,
         ML_DSA_65_Crypto_Sign_Open_Ctx},
        {"ML_DSA_87",
         FSMSW_ML_DSA_87_CRYPTO_PUBLICKEYBYTES,
         FSMSW_ML_DSA_87_CRYPTO_SECRETKEYBYTES,
         FSMSW_ML_DSA_87_CRYPTO_BYTES,
         ML_DSA_87_Crypto_Sign_KeyPair,
         ML_DSA_87_Crypto_Sign_Signature_Ctx,
         ML_DSA_87_Crypto_Sign_Ctx,
         ML_DSA_87_Crypto_Sign_Verify_Ctx,
         ML_DSA_87_Crypto_Sign_Open_Ctx},
    }};
    return cases;
}

class MlDsaContextApiTest : public ::testing::TestWithParam<MlDsaContextCase>
{
  protected:
    void SetUp() override
    {
        ASSERT_EQ(iav_primula_test::RegisterDeterministicRandomProvider(), IavStatusOk);
    }
};

// NOLINTBEGIN(readability-function-cognitive-complexity): keep the full
// context/signature contract together for each tested parameter set.
// M04 P1: direct ML-DSA *_Ctx entry points are not reached by the context-free
// FFI tests. For all three parameter sets, round-trip detached and attached
// signatures with empty, non-empty, and maximum (255-byte) contexts; then check
// deterministic rejection of a 256-byte context and mismatched logical
// signature lengths. Short-length verification still receives a full
// signature-sized backing array, avoiding an out-of-bounds test input.
TEST_P(MlDsaContextApiTest, ContextBoundariesRoundTripAndRejectInvalidLengths)
{
    static constexpr std::array<std::uint8_t, 21U> kMessage = {0x4D, 0x4C, 0x2D, 0x44, 0x53, 0x41, 0x20,
                                                               0x63, 0x6F, 0x6E, 0x74, 0x65, 0x78, 0x74,
                                                               0x20, 0x72, 0x6F, 0x75, 0x6E, 0x64, 0x74};
    static constexpr std::array<std::size_t, 3U> kContextLengths = {0U, 9U, 255U};
    const MlDsaContextCase& test_case = GetParam();
    std::vector<std::uint8_t> public_key(test_case.public_key_size);
    std::vector<std::uint8_t> secret_key(test_case.secret_key_size);
    ASSERT_NE(test_case.keypair, nullptr);
    test_case.keypair(public_key.data(), secret_key.data());

    std::array<std::uint8_t, 256U> context{};
    for (std::size_t index = 0U; index < context.size(); ++index)
    {
        context[index] = static_cast<std::uint8_t>(index);
    }

    std::vector<std::uint8_t> last_signature(test_case.signature_size);
    uint32 last_signature_len = 0U;
    for (const std::size_t context_len : kContextLengths)
    {
        std::vector<std::uint8_t> signature(test_case.signature_size);
        uint32 signature_len = 0U;
        ASSERT_EQ(test_case.sign(signature.data(),
                                 &signature_len,
                                 kMessage.data(),
                                 static_cast<uint32>(kMessage.size()),
                                 context.data(),
                                 static_cast<uint32>(context_len),
                                 secret_key.data()),
                  ERR_OK);
        ASSERT_EQ(signature_len, test_case.signature_size);
        ASSERT_EQ(test_case.verify(signature.data(),
                                   signature_len,
                                   kMessage.data(),
                                   static_cast<uint32>(kMessage.size()),
                                   context.data(),
                                   static_cast<uint32>(context_len),
                                   public_key.data()),
                  ERR_OK);

        std::vector<std::uint8_t> signed_message(test_case.signature_size + kMessage.size());
        uint32 signed_message_len = 0U;
        ASSERT_EQ(test_case.attached_sign(signed_message.data(),
                                          &signed_message_len,
                                          kMessage.data(),
                                          static_cast<uint32>(kMessage.size()),
                                          context.data(),
                                          static_cast<uint32>(context_len),
                                          secret_key.data()),
                  ERR_OK);
        ASSERT_EQ(signed_message_len, signed_message.size());
        std::vector<std::uint8_t> recovered(kMessage.size(), 0U);
        uint32 recovered_len = 0U;
        ASSERT_EQ(test_case.attached_open(recovered.data(),
                                          &recovered_len,
                                          signed_message.data(),
                                          signed_message_len,
                                          context.data(),
                                          static_cast<uint32>(context_len),
                                          public_key.data()),
                  ERR_OK);
        EXPECT_EQ(recovered_len, kMessage.size());
        EXPECT_TRUE(std::equal(kMessage.begin(), kMessage.end(), recovered.begin()));

        if (context_len == 255U)
        {
            last_signature = signature;
            last_signature_len = signature_len;
        }
    }

    // A 256-byte context exceeds the API contract. The full backing arrays and
    // valid key/signature remain in place so this asserts only the documented
    // rejection, not behavior for malformed storage.
    uint32 rejected_signature_len = 0U;
    EXPECT_EQ(test_case.sign(last_signature.data(),
                             &rejected_signature_len,
                             kMessage.data(),
                             static_cast<uint32>(kMessage.size()),
                             context.data(),
                             static_cast<uint32>(context.size()),
                             secret_key.data()),
              ERR_NOT_OK);
    EXPECT_EQ(test_case.verify(last_signature.data(),
                               last_signature_len,
                               kMessage.data(),
                               static_cast<uint32>(kMessage.size()),
                               context.data(),
                               static_cast<uint32>(context.size()),
                               public_key.data()),
              ERR_NOT_OK);

    EXPECT_NE(test_case.verify(last_signature.data(),
                               last_signature_len - 1U,
                               kMessage.data(),
                               static_cast<uint32>(kMessage.size()),
                               context.data(),
                               255U,
                               public_key.data()),
              ERR_OK);
    EXPECT_NE(test_case.verify(last_signature.data(),
                               last_signature_len + 1U,
                               kMessage.data(),
                               static_cast<uint32>(kMessage.size()),
                               context.data(),
                               255U,
                               public_key.data()),
              ERR_OK);
}
// NOLINTEND(readability-function-cognitive-complexity)

std::string MlDsaTestName(const ::testing::TestParamInfo<MlDsaContextCase>& info)
{
    return info.param.name;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables, readability-identifier-length): generated by
// gtest.
INSTANTIATE_TEST_SUITE_P(AllMlDsaParameterSets,
                         MlDsaContextApiTest,
                         ::testing::ValuesIn(MlDsaContextCases()),
                         MlDsaTestName);

}  // namespace
