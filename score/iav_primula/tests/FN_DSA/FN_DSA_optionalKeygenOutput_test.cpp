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

/// @file FN_DSA_optionalKeygenOutput_test.cpp
/// @brief Tests FN-DSA key generation when the public-key output is omitted.

#include <gtest/gtest.h>

#include <array>
#include <cstdint>

extern "C" {
#include "FN_DSA_common.h"
#include "FN_DSA_keygen.h"
#include "FsmSw_Fips202.h"
#include "score/iav_primula/include/Platform_Types.h"
}

namespace
{

constexpr uint32 kLogN = 9U;
constexpr std::size_t kDegree = 1U << kLogN;
constexpr std::array<std::uint8_t, 32U> kSeed = {
    0x46U, 0x4EU, 0x2DU, 0x44U, 0x53U, 0x41U, 0x2DU, 0x6BU, 0x65U, 0x79U, 0x67U, 0x65U, 0x6EU, 0x2DU, 0x6FU, 0x75U,
    0x74U, 0x70U, 0x75U, 0x74U, 0x2DU, 0x74U, 0x65U, 0x73U, 0x74U, 0x2DU, 0x73U, 0x65U, 0x65U, 0x64U, 0x2DU, 0x31U};

void InitializeKeygenRng(inner_shake256_context* const rng)
{
    FsmSw_Fips202_Shake256_IncInit(rng);
    FsmSw_Fips202_Shake256_IncAbsorb(rng, kSeed.data(), static_cast<uint32>(kSeed.size()));
    FsmSw_Fips202_Shake256_IncFinalize(rng);
}

// M04 P2 optional-output gap: identical seeded SHAKE states should produce
// identical private components whether h is returned or written to keygen
// scratch storage. Keep G supplied in both calls so only h's route differs.
TEST(FnDsaOptionalKeygenOutputTest, NullPublicKeyOutputPreservesPrivateKeyComponents)
{
    inner_shake256_context rng_with_h{};
    inner_shake256_context rng_without_h{};
    InitializeKeygenRng(&rng_with_h);
    InitializeKeygenRng(&rng_without_h);

    std::array<sint8, kDegree> f_with_h{};
    std::array<sint8, kDegree> g_with_h{};
    std::array<sint8, kDegree> F_with_h{};
    std::array<sint8, kDegree> G_with_h{};
    std::array<uint16, kDegree> h{};
    std::array<sint8, kDegree> f_without_h{};
    std::array<sint8, kDegree> g_without_h{};
    std::array<sint8, kDegree> F_without_h{};
    std::array<sint8, kDegree> G_without_h{};
    alignas(std::uint64_t) std::array<std::uint8_t, FN_DSA_KEYGEN_TEMP_9> tmp_with_h{};
    alignas(std::uint64_t) std::array<std::uint8_t, FN_DSA_KEYGEN_TEMP_9> tmp_without_h{};

    FN_DSA_Keygen(&rng_with_h,
                  f_with_h.data(),
                  g_with_h.data(),
                  F_with_h.data(),
                  G_with_h.data(),
                  h.data(),
                  kLogN,
                  tmp_with_h.data());
    FN_DSA_Keygen(&rng_without_h,
                  f_without_h.data(),
                  g_without_h.data(),
                  F_without_h.data(),
                  G_without_h.data(),
                  nullptr,
                  kLogN,
                  tmp_without_h.data());

    EXPECT_EQ(f_with_h, f_without_h);
    EXPECT_EQ(g_with_h, g_without_h);
    EXPECT_EQ(F_with_h, F_without_h);
    EXPECT_EQ(G_with_h, G_without_h);
}

}  // namespace
