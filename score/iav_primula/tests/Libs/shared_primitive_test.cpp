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

/// @file shared_primitive_test.cpp
/// @brief Known-answer and incremental tests for IAV shared primitives and the RNG adapter.

#include "score/iav_primula/include/iav_primula_ffi.h"

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
#include "FsmSw_CommonLib.h"
#include "FsmSw_Fips202.h"
#include "FsmSw_sha2.h"
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
constexpr std::size_t kDigestSize = 32U;
constexpr std::size_t kSha256BlockSize = 64U;
constexpr std::size_t kSha256BlockBoundaryInputSize = kSha256BlockSize + 1U;
constexpr std::size_t kSha3Rate = SHA3_256_RATE;
constexpr std::size_t kSha3BoundaryInputSize = kSha3Rate + 1U;
constexpr std::size_t kShakeOutputSize = 32U;
constexpr std::size_t kShakeFirstChunkSize = 7U;
constexpr std::size_t kShakeSecondChunkSize = kShakeOutputSize - kShakeFirstChunkSize;
constexpr std::uint8_t kInitialOutputByte = 0xA5U;

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

// NOLINTNEXTLINE(cert-err58-cpp, cppcoreguidelines-owning-memory): gtest statically registers test factories.
TEST(Sha2Test, Sha256KnownAnswerAndIncrementalCloneAcrossBlockBoundary)
{
    static constexpr std::array<std::uint8_t, 3U> kMessage = {0x61U, 0x62U, 0x63U};
    static constexpr std::array<std::uint8_t, kDigestSize> kSha256Abc = {
        0xBAU, 0x78U, 0x16U, 0xBFU, 0x8FU, 0x01U, 0xCFU, 0xEAU, 0x41U, 0x41U, 0x40U, 0xDEU, 0x5DU, 0xAEU, 0x22U, 0x23U,
        0xB0U, 0x03U, 0x61U, 0xA3U, 0x96U, 0x17U, 0x7AU, 0x9CU, 0xB4U, 0x10U, 0xFFU, 0x61U, 0xF2U, 0x00U, 0x15U, 0xADU};
    std::array<std::uint8_t, kSha256Abc.size()> digest{};

    FsmSw_Sha256(digest.data(), kMessage.data(), static_cast<uint32>(kMessage.size()));
    EXPECT_EQ(std::memcmp(digest.data(), kSha256Abc.data(), digest.size()), 0);

    std::array<std::uint8_t, kSha256BlockBoundaryInputSize> block_boundary_message{};
    std::size_t byte_value = 0U;
    for (std::uint8_t& byte : block_boundary_message)
    {
        byte = static_cast<std::uint8_t>(byte_value);
        ++byte_value;
    }
    std::array<std::uint8_t, kDigestSize> one_shot{};
    std::array<std::uint8_t, kDigestSize> incremental{};
    std::array<std::uint8_t, kDigestSize> cloned_incremental{};
    FsmSw_Sha256(one_shot.data(), block_boundary_message.data(), static_cast<uint32>(block_boundary_message.size()));

    sha256ctx state{};
    sha256ctx cloned_state{};
    FsmSw_Sha256_IncInit(&state);
    FsmSw_Sha256_IncBlocks(&state, block_boundary_message.data(), 1U);
    FsmSw_Sha256_IncCtxClone(&cloned_state, &state);
    FsmSw_Sha256_IncFinalize(incremental.data(), &state, &block_boundary_message[kSha256BlockSize], 1U);
    FsmSw_Sha256_IncFinalize(cloned_incremental.data(), &cloned_state, &block_boundary_message[kSha256BlockSize], 1U);

    EXPECT_EQ(std::memcmp(one_shot.data(), incremental.data(), one_shot.size()), 0);
    EXPECT_EQ(std::memcmp(one_shot.data(), cloned_incremental.data(), one_shot.size()), 0);
}

// NOLINTNEXTLINE(cert-err58-cpp, cppcoreguidelines-owning-memory): gtest statically registers test factories.
TEST(Fips202Test, Sha3KnownAnswerAndIncrementalCloneAtRateBoundary)
{
    static constexpr std::array<std::uint8_t, 1U> kEmptyMessage = {0U};
    static constexpr std::array<std::uint8_t, kDigestSize> kSha3_256Empty = {
        0xA7U, 0xFFU, 0xC6U, 0xF8U, 0xBFU, 0x1EU, 0xD7U, 0x66U, 0x51U, 0xC1U, 0x47U, 0x56U, 0xA0U, 0x61U, 0xD6U, 0x62U,
        0xF5U, 0x80U, 0xFFU, 0x4DU, 0xE4U, 0x3BU, 0x49U, 0xFAU, 0x82U, 0xD8U, 0x0AU, 0x4BU, 0x80U, 0xF8U, 0x43U, 0x4AU};
    std::array<std::uint8_t, kDigestSize> digest{};

    FsmSw_Fips202_Sha3_256(digest.data(), kEmptyMessage.data(), 0U);
    EXPECT_EQ(std::memcmp(digest.data(), kSha3_256Empty.data(), digest.size()), 0);

    std::array<std::uint8_t, kSha3BoundaryInputSize> message{};
    std::size_t byte_value = 0U;
    for (std::uint8_t& byte : message)
    {
        byte = static_cast<std::uint8_t>(byte_value);
        ++byte_value;
    }
    std::array<std::uint8_t, kDigestSize> one_shot{};
    std::array<std::uint8_t, kDigestSize> incremental{};
    std::array<std::uint8_t, kDigestSize> cloned_incremental{};
    FsmSw_Fips202_Sha3_256(one_shot.data(), message.data(), static_cast<uint32>(message.size()));

    sha3_256incctx state{};
    sha3_256incctx cloned_state{};
    FsmSw_Fips202_Sha3_256_IncInit(&state);
    FsmSw_Fips202_Sha3_256_IncAbsorb(&state, message.data(), kSha3Rate - 1U);
    FsmSw_Fips202_Sha3_256_IncCtxClone(&cloned_state, &state);
    FsmSw_Fips202_Sha3_256_IncAbsorb(&state, &message[kSha3Rate - 1U], 2U);
    FsmSw_Fips202_Sha3_256_IncAbsorb(&cloned_state, &message[kSha3Rate - 1U], 2U);
    FsmSw_Fips202_Sha3_256_IncFinalize(incremental.data(), &state);
    FsmSw_Fips202_Sha3_256_IncFinalize(cloned_incremental.data(), &cloned_state);

    EXPECT_EQ(std::memcmp(one_shot.data(), incremental.data(), one_shot.size()), 0);
    EXPECT_EQ(std::memcmp(one_shot.data(), cloned_incremental.data(), one_shot.size()), 0);
}

// NOLINTNEXTLINE(cert-err58-cpp, cppcoreguidelines-owning-memory): gtest statically registers test factories.
TEST(Fips202Test, Shake128KnownAnswerAndChunkedSqueeze)
{
    static constexpr std::array<std::uint8_t, 1U> kEmptyMessage = {0U};
    static constexpr std::array<std::uint8_t, kShakeOutputSize> kShake128Empty = {
        0x7FU, 0x9CU, 0x2BU, 0xA4U, 0xE8U, 0x8FU, 0x82U, 0x7DU, 0x61U, 0x60U, 0x45U, 0x50U, 0x76U, 0x05U, 0x85U, 0x3EU,
        0xD7U, 0x3BU, 0x80U, 0x93U, 0xF6U, 0xEFU, 0xBCU, 0x88U, 0xEBU, 0x1AU, 0x6EU, 0xACU, 0xFAU, 0x66U, 0xEFU, 0x26U};
    std::array<std::uint8_t, kShakeOutputSize> one_shot{};
    FsmSw_Fips202_Shake128(one_shot.data(), static_cast<uint32>(one_shot.size()), kEmptyMessage.data(), 0U);
    EXPECT_EQ(std::memcmp(one_shot.data(), kShake128Empty.data(), one_shot.size()), 0);

    shake128incctx state{};
    shake128incctx cloned_state{};
    FsmSw_Fips202_Shake128_IncInit(&state);
    FsmSw_Fips202_Shake128_IncAbsorb(&state, kEmptyMessage.data(), 0U);
    FsmSw_Fips202_Shake128_IncFinalize(&state);
    FsmSw_Fips202_Shake128_IncCtxClone(&cloned_state, &state);

    std::array<std::uint8_t, kShakeOutputSize> chunked{};
    std::array<std::uint8_t, kShakeOutputSize> cloned{};
    FsmSw_Fips202_Shake128_IncSqueeze(chunked.data(), kShakeFirstChunkSize, &state);
    FsmSw_Fips202_Shake128_IncSqueeze(&chunked[kShakeFirstChunkSize], kShakeSecondChunkSize, &state);
    FsmSw_Fips202_Shake128_IncSqueeze(cloned.data(), static_cast<uint32>(cloned.size()), &cloned_state);

    EXPECT_EQ(std::memcmp(chunked.data(), kShake128Empty.data(), chunked.size()), 0);
    EXPECT_EQ(std::memcmp(cloned.data(), kShake128Empty.data(), cloned.size()), 0);
}

// NOLINTNEXTLINE(cert-err58-cpp, cppcoreguidelines-owning-memory): gtest statically registers test factories.
TEST(CommonLibAdapterTest, RandomBytesUsesRegisteredPlatformProvider)
{
    ASSERT_EQ(RegisterTestRandomBytesProvider(), IavStatusOk);

    std::array<std::uint8_t, kDigestSize> output{};
    output.fill(kInitialOutputByte);
    const std::array<std::uint8_t, kDigestSize> unchanged = output;
    EXPECT_EQ(FsmSw_CommonLib_RandomBytes(output.data(), static_cast<uint32>(output.size())), ERR_OK);
    EXPECT_NE(output, unchanged);
    EXPECT_EQ(FsmSw_CommonLib_RandomBytes(nullptr, 0U), ERR_OK);
}

}  // namespace
