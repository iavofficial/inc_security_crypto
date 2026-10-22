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

/// @file SLH_DSA_attachedMessage_test.cpp
/// @brief Valid attached-message open/sign tests for SLH-DSA variants.

#include "score/iav_primula/tests/common/coverage_test_support.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include "FsmSw_CommonLib.h"
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
#include "score/iav_primula/include/iav_primula_ffi.h"

namespace
{

using KeyPairOperation = void (*)(uint8*, uint8*);
using DetachedSignOperation = void (*)(uint8*, uint32*, const uint8*, uint32, const uint8*);
using AttachedSignOperation = void (*)(uint8*, uint32*, const uint8*, uint32, const uint8*);
using AttachedOpenOperation = uint8 (*)(uint8*, uint32*, const uint8*, uint32, const uint8*);

struct SlhDsaCase
{
    const char* name = "";
    std::size_t public_key_size = 0U;
    std::size_t secret_key_size = 0U;
    std::size_t signature_size = 0U;
    KeyPairOperation keypair = nullptr;
    DetachedSignOperation detached_sign = nullptr;
    AttachedSignOperation attached_sign = nullptr;
    AttachedOpenOperation attached_open = nullptr;
};

constexpr std::size_t kSlhDsaVariantCount = 12U;

const std::array<SlhDsaCase, kSlhDsaVariantCount>& SlhDsaCases()
{
    static const std::array<SlhDsaCase, kSlhDsaVariantCount> cases = {{
        {"SLH_DSA_SHA2_128f",
         SLH_DSA_SHA2_128FSIMPLE_PK_BYTES,
         SLH_DSA_SHA2_128FSIMPLE_SK_BYTES,
         SLH_DSA_SHA2_128FSIMPLE_BYTES,
         SLH_DSA_SHA2_128fSimple_Crypto_Sign_KeyPair,
         SLH_DSA_SHA2_128fSimple_Crypto_Sign_Signature,
         SLH_DSA_SHA2_128fSimple_Crypto_Sign,
         SLH_DSA_SHA2_128fSimple_Crypto_Sign_Open},
        {"SLH_DSA_SHA2_128s",
         SLH_DSA_SHA2_128SSIMPLE_PK_BYTES,
         SLH_DSA_SHA2_128SSIMPLE_SK_BYTES,
         SLH_DSA_SHA2_128SSIMPLE_BYTES,
         SLH_DSA_SHA2_128sSimple_Crypto_Sign_KeyPair,
         SLH_DSA_SHA2_128sSimple_Crypto_Sign_Signature,
         SLH_DSA_SHA2_128sSimple_Crypto_Sign,
         SLH_DSA_SHA2_128sSimple_Crypto_Sign_Open},
        {"SLH_DSA_SHA2_192f",
         SLH_DSA_SHA2_192FSIMPLE_PK_BYTES,
         SLH_DSA_SHA2_192FSIMPLE_SK_BYTES,
         SLH_DSA_SHA2_192FSIMPLE_BYTES,
         SLH_DSA_SHA2_192fSimple_Crypto_Sign_KeyPair,
         SLH_DSA_SHA2_192fSimple_Crypto_Sign_Signature,
         SLH_DSA_SHA2_192fSimple_Crypto_Sign,
         SLH_DSA_SHA2_192fSimple_Crypto_Sign_Open},
        {"SLH_DSA_SHA2_192s",
         SLH_DSA_SHA2_192SSIMPLE_PK_BYTES,
         SLH_DSA_SHA2_192SSIMPLE_SK_BYTES,
         SLH_DSA_SHA2_192SSIMPLE_BYTES,
         SLH_DSA_SHA2_192sSimple_Crypto_Sign_KeyPair,
         SLH_DSA_SHA2_192sSimple_Crypto_Sign_Signature,
         SLH_DSA_SHA2_192sSimple_Crypto_Sign,
         SLH_DSA_SHA2_192sSimple_Crypto_Sign_Open},
        {"SLH_DSA_SHA2_256f",
         SLH_DSA_SHA2_256FSIMPLE_PK_BYTES,
         SLH_DSA_SHA2_256FSIMPLE_SK_BYTES,
         SLH_DSA_SHA2_256FSIMPLE_BYTES,
         SLH_DSA_SHA2_256fSimple_Crypto_Sign_KeyPair,
         SLH_DSA_SHA2_256fSimple_Crypto_Sign_Signature,
         SLH_DSA_SHA2_256fSimple_Crypto_Sign,
         SLH_DSA_SHA2_256fSimple_Crypto_Sign_Open},
        {"SLH_DSA_SHA2_256s",
         SLH_DSA_SHA2_256SSIMPLE_PK_BYTES,
         SLH_DSA_SHA2_256SSIMPLE_SK_BYTES,
         SLH_DSA_SHA2_256SSIMPLE_BYTES,
         SLH_DSA_SHA2_256sSimple_Crypto_Sign_KeyPair,
         SLH_DSA_SHA2_256sSimple_Crypto_Sign_Signature,
         SLH_DSA_SHA2_256sSimple_Crypto_Sign,
         SLH_DSA_SHA2_256sSimple_Crypto_Sign_Open},
        {"SLH_DSA_SHAKE_128f",
         SLH_DSA_SHAKE_128FSIMPLE_PK_BYTES,
         SLH_DSA_SHAKE_128FSIMPLE_SK_BYTES,
         SLH_DSA_SHAKE_128FSIMPLE_BYTES,
         SLH_DSA_SHAKE_128fSimple_Crypto_Sign_KeyPair,
         SLH_DSA_SHAKE_128fSimple_Crypto_Sign_Signature,
         SLH_DSA_SHAKE_128fSimple_Crypto_Sign,
         SLH_DSA_SHAKE_128fSimple_Crypto_Sign_Open},
        {"SLH_DSA_SHAKE_128s",
         SLH_DSA_SHAKE_128SSIMPLE_PK_BYTES,
         SLH_DSA_SHAKE_128SSIMPLE_SK_BYTES,
         SLH_DSA_SHAKE_128SSIMPLE_BYTES,
         SLH_DSA_SHAKE_128sSimple_Crypto_Sign_KeyPair,
         SLH_DSA_SHAKE_128sSimple_Crypto_Sign_Signature,
         SLH_DSA_SHAKE_128sSimple_Crypto_Sign,
         SLH_DSA_SHAKE_128sSimple_Crypto_Sign_Open},
        {"SLH_DSA_SHAKE_192f",
         SLH_DSA_SHAKE_192FSIMPLE_PK_BYTES,
         SLH_DSA_SHAKE_192FSIMPLE_SK_BYTES,
         SLH_DSA_SHAKE_192FSIMPLE_BYTES,
         SLH_DSA_SHAKE_192fSimple_Crypto_Sign_KeyPair,
         SLH_DSA_SHAKE_192fSimple_Crypto_Sign_Signature,
         SLH_DSA_SHAKE_192fSimple_Crypto_Sign,
         SLH_DSA_SHAKE_192fSimple_Crypto_Sign_Open},
        {"SLH_DSA_SHAKE_192s",
         SLH_DSA_SHAKE_192SSIMPLE_PK_BYTES,
         SLH_DSA_SHAKE_192SSIMPLE_SK_BYTES,
         SLH_DSA_SHAKE_192SSIMPLE_BYTES,
         SLH_DSA_SHAKE_192sSimple_Crypto_Sign_KeyPair,
         SLH_DSA_SHAKE_192sSimple_Crypto_Sign_Signature,
         SLH_DSA_SHAKE_192sSimple_Crypto_Sign,
         SLH_DSA_SHAKE_192sSimple_Crypto_Sign_Open},
        {"SLH_DSA_SHAKE_256f",
         SLH_DSA_SHAKE_256FSIMPLE_PK_BYTES,
         SLH_DSA_SHAKE_256FSIMPLE_SK_BYTES,
         SLH_DSA_SHAKE_256FSIMPLE_BYTES,
         SLH_DSA_SHAKE_256fSimple_Crypto_Sign_KeyPair,
         SLH_DSA_SHAKE_256fSimple_Crypto_Sign_Signature,
         SLH_DSA_SHAKE_256fSimple_Crypto_Sign,
         SLH_DSA_SHAKE_256fSimple_Crypto_Sign_Open},
        {"SLH_DSA_SHAKE_256s",
         SLH_DSA_SHAKE_256SSIMPLE_PK_BYTES,
         SLH_DSA_SHAKE_256SSIMPLE_SK_BYTES,
         SLH_DSA_SHAKE_256SSIMPLE_BYTES,
         SLH_DSA_SHAKE_256sSimple_Crypto_Sign_KeyPair,
         SLH_DSA_SHAKE_256sSimple_Crypto_Sign_Signature,
         SLH_DSA_SHAKE_256sSimple_Crypto_Sign,
         SLH_DSA_SHAKE_256sSimple_Crypto_Sign_Open},
    }};
    return cases;
}

class SlhDsaAttachedMessageTest : public ::testing::TestWithParam<SlhDsaCase>
{
  protected:
    void SetUp() override
    {
        ASSERT_EQ(iav_primula_test::RegisterDeterministicRandomProvider(), IavStatusOk);
    }
};

// M04 P2: attached Crypto_Sign_Open paths are absent from M02, while detached
// round trips already exercise all twelve variants. For each variant, produce
// one valid detached signature and reuse it in signature||message form, which
// covers the open/recovery path without an additional attached-sign operation.
// Inputs and backing buffers are valid and fully sized; malformed-input behavior
// is intentionally outside this functional milestone.
TEST_P(SlhDsaAttachedMessageTest, OpensDetachedSignaturePackedWithItsMessage)
{
    static constexpr std::array<std::uint8_t, 17U> kMessage = {0x53U,
                                                               0x4CU,
                                                               0x48U,
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
                                                               0x21U};
    const SlhDsaCase& test_case = GetParam();
    std::vector<std::uint8_t> public_key(test_case.public_key_size);
    std::vector<std::uint8_t> secret_key(test_case.secret_key_size);
    std::vector<std::uint8_t> signature(test_case.signature_size);
    ASSERT_NE(test_case.keypair, nullptr);
    test_case.keypair(public_key.data(), secret_key.data());

    uint32 signature_len = 0U;
    test_case.detached_sign(
        signature.data(), &signature_len, kMessage.data(), static_cast<uint32>(kMessage.size()), secret_key.data());
    ASSERT_EQ(signature_len, test_case.signature_size);

    std::vector<std::uint8_t> signed_message(signature_len + kMessage.size());
    std::copy(signature.begin(), signature.end(), signed_message.begin());
    std::copy(kMessage.begin(), kMessage.end(), signed_message.begin() + signature_len);
    std::vector<std::uint8_t> recovered(kMessage.size(), 0U);
    uint32 recovered_len = 0U;
    ASSERT_EQ(test_case.attached_open(recovered.data(),
                                      &recovered_len,
                                      signed_message.data(),
                                      static_cast<uint32>(signed_message.size()),
                                      public_key.data()),
              ERR_OK);
    EXPECT_EQ(recovered_len, kMessage.size());
    EXPECT_TRUE(std::equal(kMessage.begin(), kMessage.end(), recovered.begin()));
}

std::string SlhDsaTestName(const ::testing::TestParamInfo<SlhDsaCase>& info)
{
    return info.param.name;
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables, readability-identifier-length): generated by
// gtest.
INSTANTIATE_TEST_SUITE_P(AllSlhDsaVariants,
                         SlhDsaAttachedMessageTest,
                         ::testing::ValuesIn(SlhDsaCases()),
                         SlhDsaTestName);

class SlhDsaAttachedSignTest : public ::testing::TestWithParam<SlhDsaCase>
{
  protected:
    void SetUp() override
    {
        ASSERT_EQ(iav_primula_test::RegisterDeterministicRandomProvider(), IavStatusOk);
    }
};

// M04 P2: attached signing is reachable normal behavior but repeats the costly
// SLH-DSA signing operation. Cover representative SHA2/SHAKE and fast/small
// parameter choices, then open the resulting signature||message and check exact
// length/content recovery; all variants' open functions are exercised above.
TEST_P(SlhDsaAttachedSignTest, SignsAndOpensAttachedMessage)
{
    static constexpr std::array<std::uint8_t, 18U> kMessage = {0x53U,
                                                               0x4CU,
                                                               0x48U,
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
                                                               0x73U,
                                                               0x69U,
                                                               0x67U,
                                                               0x6EU,
                                                               0x21U};
    const SlhDsaCase& test_case = GetParam();
    std::vector<std::uint8_t> public_key(test_case.public_key_size);
    std::vector<std::uint8_t> secret_key(test_case.secret_key_size);
    ASSERT_NE(test_case.keypair, nullptr);
    test_case.keypair(public_key.data(), secret_key.data());

    std::vector<std::uint8_t> signed_message(test_case.signature_size + kMessage.size());
    uint32 signed_message_len = 0U;
    test_case.attached_sign(signed_message.data(),
                            &signed_message_len,
                            kMessage.data(),
                            static_cast<uint32>(kMessage.size()),
                            secret_key.data());
    ASSERT_EQ(signed_message_len, signed_message.size());

    std::vector<std::uint8_t> recovered(kMessage.size(), 0U);
    uint32 recovered_len = 0U;
    ASSERT_EQ(test_case.attached_open(
                  recovered.data(), &recovered_len, signed_message.data(), signed_message_len, public_key.data()),
              ERR_OK);
    EXPECT_EQ(recovered_len, kMessage.size());
    EXPECT_TRUE(std::equal(kMessage.begin(), kMessage.end(), recovered.begin()));
}

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables, readability-identifier-length): generated by
// gtest.
INSTANTIATE_TEST_SUITE_P(RepresentativeSha2AndShakeSizes,
                         SlhDsaAttachedSignTest,
                         ::testing::Values(SlhDsaCases()[0U], SlhDsaCases()[7U]),
                         SlhDsaTestName);

}  // namespace
