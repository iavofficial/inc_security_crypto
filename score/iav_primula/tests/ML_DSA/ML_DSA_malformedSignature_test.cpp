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

/// @file ML_DSA_malformedSignature_test.cpp
/// @brief Tests public verification rejection of malformed ML-DSA signatures.

#include "score/iav_primula/include/iav_primula_ffi.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" {
#include "FsmSw_CommonLib.h"
#include "ML_DSA_44_api.h"
#include "ML_DSA_44_params.h"
#include "ML_DSA_65_api.h"
#include "ML_DSA_65_params.h"
#include "ML_DSA_87_api.h"
#include "ML_DSA_87_params.h"
#include "score/iav_primula/include/Platform_Types.h"
}

namespace
{

constexpr std::uint32_t kErrNotOk = ERR_NOT_OK;
constexpr std::array<std::uint8_t, 15U> kMessage =
    {0x4Du, 0x4Cu, 0x2Du, 0x44u, 0x53u, 0x41u, 0x2Du, 0x6Du, 0x61u, 0x6Fu, 0x6Cu, 0x66u, 0x6Fu, 0x72u, 0x6Du};

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

using KeyPairOperation = void (*)(uint8*, uint8*);
using DetachedSignOperation = uint8 (*)(uint8*, uint32*, const uint8*, uint32, const uint8*);
using DetachedVerifyOperation = uint8 (*)(const uint8*, uint32, const uint8*, uint32, const uint8*);

struct MlDsaCase
{
    const char* name = "";
    std::size_t public_key_size = 0U;
    std::size_t secret_key_size = 0U;
    std::size_t signature_size = 0U;
    std::size_t ctilde_size = 0U;
    std::size_t hint_offset = 0U;
    std::size_t omega = 0U;
    std::size_t k = 0U;
    KeyPairOperation keypair = nullptr;
    DetachedSignOperation sign = nullptr;
    DetachedVerifyOperation verify = nullptr;
};

const std::array<MlDsaCase, 3U>& MlDsaCases()
{
    static const std::array<MlDsaCase, 3U> cases = {{
        {"ML_DSA_44",
         FSMSW_ML_DSA_44_CRYPTO_PUBLICKEYBYTES,
         FSMSW_ML_DSA_44_CRYPTO_SECRETKEYBYTES,
         FSMSW_ML_DSA_44_CRYPTO_BYTES,
         CTILDEBYTES_ML_DSA_44,
         CTILDEBYTES_ML_DSA_44 + (L_ML_DSA_44 * POLYZ_PACKEDBYTES_ML_DSA_44),
         OMEGA_ML_DSA_44,
         K_ML_DSA_44,
         ML_DSA_44_Crypto_Sign_KeyPair,
         ML_DSA_44_Crypto_Sign_Signature,
         ML_DSA_44_Crypto_Sign_Verify},
        {"ML_DSA_65",
         FSMSW_ML_DSA_65_CRYPTO_PUBLICKEYBYTES,
         FSMSW_ML_DSA_65_CRYPTO_SECRETKEYBYTES,
         FSMSW_ML_DSA_65_CRYPTO_BYTES,
         CTILDEBYTES_ML_DSA_65,
         CTILDEBYTES_ML_DSA_65 + (L_ML_DSA_65 * POLYZ_PACKEDBYTES_ML_DSA_65),
         OMEGA_ML_DSA_65,
         K_ML_DSA_65,
         ML_DSA_65_Crypto_Sign_KeyPair,
         ML_DSA_65_Crypto_Sign_Signature,
         ML_DSA_65_Crypto_Sign_Verify},
        {"ML_DSA_87",
         FSMSW_ML_DSA_87_CRYPTO_PUBLICKEYBYTES,
         FSMSW_ML_DSA_87_CRYPTO_SECRETKEYBYTES,
         FSMSW_ML_DSA_87_CRYPTO_BYTES,
         CTILDEBYTES_ML_DSA_87,
         CTILDEBYTES_ML_DSA_87 + (L_ML_DSA_87 * POLYZ_PACKEDBYTES_ML_DSA_87),
         OMEGA_ML_DSA_87,
         K_ML_DSA_87,
         ML_DSA_87_Crypto_Sign_KeyPair,
         ML_DSA_87_Crypto_Sign_Signature,
         ML_DSA_87_Crypto_Sign_Verify},
    }};
    return cases;
}

class MlDsaMalformedSignatureTest : public ::testing::TestWithParam<MlDsaCase>
{
  protected:
    void SetUp() override
    {
        ASSERT_EQ(RegisterTestRandomBytesProvider(), IavStatusOk);
    }
};

// M04 P2 ML-DSA packing gap: public verification must reject malformed hint
// endpoints, non-increasing hint indices, nonzero unused indices, and a packed
// z coefficient outside the norm bound. Mutations retain full signature size
// and keep every crafted index inside the hint-vector bounds.
TEST_P(MlDsaMalformedSignatureTest, RejectsMalformedHintsAndOutOfRangeZ)
{
    const MlDsaCase& test_case = GetParam();
    std::vector<std::uint8_t> public_key(test_case.public_key_size);
    std::vector<std::uint8_t> secret_key(test_case.secret_key_size);
    std::vector<std::uint8_t> signature(test_case.signature_size);
    test_case.keypair(public_key.data(), secret_key.data());

    uint32 signature_len = 0U;
    ASSERT_EQ(ERR_OK,
              test_case.sign(signature.data(),
                             &signature_len,
                             kMessage.data(),
                             static_cast<uint32>(kMessage.size()),
                             secret_key.data()));
    ASSERT_EQ(test_case.signature_size, signature_len);
    ASSERT_EQ(
        ERR_OK,
        test_case.verify(
            signature.data(), signature_len, kMessage.data(), static_cast<uint32>(kMessage.size()), public_key.data()));

    std::vector<std::uint8_t> malformed = signature;
    malformed[test_case.hint_offset + test_case.omega] = static_cast<std::uint8_t>(test_case.omega + 1U);
    EXPECT_EQ(
        test_case.verify(
            malformed.data(), signature_len, kMessage.data(), static_cast<uint32>(kMessage.size()), public_key.data()),
        kErrNotOk);

    malformed = signature;
    malformed[test_case.hint_offset] = 7U;
    malformed[test_case.hint_offset + 1U] = 7U;
    malformed[test_case.hint_offset + test_case.omega] = 2U;
    EXPECT_EQ(
        test_case.verify(
            malformed.data(), signature_len, kMessage.data(), static_cast<uint32>(kMessage.size()), public_key.data()),
        kErrNotOk);

    malformed = signature;
    std::fill(malformed.begin() + static_cast<std::ptrdiff_t>(test_case.hint_offset),
              malformed.begin() + static_cast<std::ptrdiff_t>(test_case.hint_offset + test_case.omega + test_case.k),
              0U);
    malformed[test_case.hint_offset] = 1U;
    EXPECT_EQ(
        test_case.verify(
            malformed.data(), signature_len, kMessage.data(), static_cast<uint32>(kMessage.size()), public_key.data()),
        kErrNotOk);

    malformed = signature;
    std::fill(malformed.begin() + static_cast<std::ptrdiff_t>(test_case.ctilde_size),
              malformed.begin() + static_cast<std::ptrdiff_t>(test_case.hint_offset),
              0U);
    EXPECT_EQ(
        test_case.verify(
            malformed.data(), signature_len, kMessage.data(), static_cast<uint32>(kMessage.size()), public_key.data()),
        kErrNotOk);
}

INSTANTIATE_TEST_SUITE_P(AllSupportedParameterSets,
                         MlDsaMalformedSignatureTest,
                         ::testing::ValuesIn(MlDsaCases()),
                         [](const ::testing::TestParamInfo<MlDsaCase>& info) {
                             return info.param.name;
                         });

}  // namespace
