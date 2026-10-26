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

/// @file FN_DSA_primitiveBoundary_test.cpp
/// @brief Tests FN-DSA norm and PRNG refill boundaries.

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" {
#include "FN_DSA_common.h"
#include "FN_DSA_rng.h"
#include "FsmSw_Fips202.h"
#include "score/iav_primula/include/Platform_Types.h"
}

namespace
{

constexpr std::array<std::uint8_t, 32U> kSeed = {
    0x46U, 0x4EU, 0x2DU, 0x44U, 0x53U, 0x41U, 0x2DU, 0x50U, 0x52U, 0x4EU, 0x47U, 0x2DU, 0x62U, 0x6FU, 0x75U, 0x6EU,
    0x64U, 0x61U, 0x72U, 0x79U, 0x2DU, 0x74U, 0x65U, 0x73U, 0x74U, 0x2DU, 0x73U, 0x65U, 0x65U, 0x64U, 0x2DU, 0x31U};

prng InitializePrng()
{
    inner_shake256_context source{};
    FsmSw_Fips202_Shake256_IncInit(&source);
    FsmSw_Fips202_Shake256_IncAbsorb(&source, kSeed.data(), static_cast<uint32>(kSeed.size()));
    FsmSw_Fips202_Shake256_IncFinalize(&source);

    prng generator{};
    FN_DSA_Prng_Init(&generator, &source);
    return generator;
}

// M04 P3 norm-helper gap: the acceptance bound is inclusive for both supported
// degrees. Zero and exact-bound inputs must pass, while one over must reject.
TEST(FnDsaPrimitiveBoundaryTest, IsShortHalfUsesInclusiveBoundsForSupportedDegrees)
{
    constexpr std::array<std::uint32_t, 2U> kLogNValues = {9U, 10U};
    constexpr std::array<std::uint32_t, 2U> kSquaredNormBounds = {34034726U, 70265242U};
    std::array<std::int16_t, 1U << 10U> zero_half{};

    for (std::size_t index = 0U; index < kLogNValues.size(); ++index)
    {
        EXPECT_EQ(1, FN_DSA_IsShortHalf(0U, zero_half.data(), kLogNValues[index]));
        EXPECT_EQ(1, FN_DSA_IsShortHalf(kSquaredNormBounds[index], zero_half.data(), kLogNValues[index]));
        EXPECT_EQ(0, FN_DSA_IsShortHalf(kSquaredNormBounds[index] + 1U, zero_half.data(), kLogNValues[index]));
    }
}

// M04 P3 PRNG gap: one request spanning the 512-byte refill boundary must be
// byte-for-byte equivalent to chunked reads over the same deterministically
// seeded stream.
TEST(FnDsaPrimitiveBoundaryTest, PrngGetBytesMatchesChunkedReadsAcrossRefill)
{
    constexpr std::size_t kRequestedBytes = FN_DSA_BUF_SIZE + 1U;
    prng single_read = InitializePrng();
    prng chunked_reads = InitializePrng();
    std::vector<std::uint8_t> single_output(kRequestedBytes);
    std::vector<std::uint8_t> chunked_output(kRequestedBytes);

    FN_DSA_Prng_GetBytes(&single_read, single_output.data(), static_cast<uint32>(single_output.size()));
    FN_DSA_Prng_GetBytes(&chunked_reads, chunked_output.data(), FN_DSA_BUF_SIZE - 1U);
    FN_DSA_Prng_GetBytes(&chunked_reads, chunked_output.data() + FN_DSA_BUF_SIZE - 1U, 2U);

    EXPECT_EQ(single_output, chunked_output);
}

// M04 P3 PRNG gap: GetU64 refills when fewer than nine bytes remain. Identical
// streams positioned at that threshold must refill to the same first word and
// advance their cursors consistently.
TEST(FnDsaPrimitiveBoundaryTest, PrngGetU64RefillsAtTheLastNineByteThreshold)
{
    constexpr uint32 kBytesBeforeThreshold = FN_DSA_BUF_SIZE - 9U;
    prng first = InitializePrng();
    prng second = InitializePrng();
    std::array<std::uint8_t, kBytesBeforeThreshold> discarded_first{};
    std::array<std::uint8_t, kBytesBeforeThreshold> discarded_second{};
    FN_DSA_Prng_GetBytes(&first, discarded_first.data(), kBytesBeforeThreshold);
    FN_DSA_Prng_GetBytes(&second, discarded_second.data(), kBytesBeforeThreshold);

    EXPECT_EQ(FN_DSA_Prng_GetU64(&first), FN_DSA_Prng_GetU64(&second));
    EXPECT_EQ(8U, first.ptr);
    EXPECT_EQ(first.ptr, second.ptr);
}

}  // namespace
