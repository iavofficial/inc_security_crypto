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

/// @file rng_unconfigured_ffi_test.cpp
/// @brief Verify entropy-dependent FFI operations fail closed without a provider.

#include "score/iav_primula/include/iav_primula_ffi.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace
{

constexpr std::size_t kMlKem512PublicKeySize = 800U;
constexpr std::size_t kMlKem512CiphertextSize = 768U;
constexpr std::size_t kSharedSecretSize = 32U;
constexpr std::uint8_t kCanary = 0xA5U;

TEST(RngUnconfiguredFfiTest, KeyGenerationFailsAndLeavesOutputHandlesNull)
{
    iav_primula_key_handle* signature_key = nullptr;
    iav_primula_key_handle* kem_key = nullptr;

    EXPECT_EQ(iav_keypair_generate(IavAlgorithmMlDsa44, &signature_key), IavStatusCryptoFailure);
    EXPECT_EQ(signature_key, nullptr);
    EXPECT_EQ(iav_kem_keypair_generate(IavAlgorithmMlKem512, &kem_key), IavStatusCryptoFailure);
    EXPECT_EQ(kem_key, nullptr);
}

TEST(RngUnconfiguredFfiTest, EncapsulationFailsWithoutChangingOutputBuffersOrLengths)
{
    std::array<std::uint8_t, kMlKem512PublicKeySize> public_key{};
    std::array<std::uint8_t, kMlKem512CiphertextSize + 2U> ciphertext{};
    std::array<std::uint8_t, kSharedSecretSize + 2U> shared_secret{};
    ciphertext.fill(kCanary);
    shared_secret.fill(kCanary);

    std::size_t ciphertext_len = kMlKem512CiphertextSize;
    std::size_t shared_secret_len = kSharedSecretSize;
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic): reserve a byte of canary on each side.
    const iav_status status = iav_kem_encapsulate(IavAlgorithmMlKem512,
                                                  public_key.data(),
                                                  public_key.size(),
                                                  ciphertext.data() + 1U,
                                                  &ciphertext_len,
                                                  shared_secret.data() + 1U,
                                                  &shared_secret_len);
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    EXPECT_EQ(status, IavStatusCryptoFailure);
    EXPECT_EQ(ciphertext_len, kMlKem512CiphertextSize);
    EXPECT_EQ(shared_secret_len, kSharedSecretSize);
    EXPECT_TRUE(std::all_of(ciphertext.begin(), ciphertext.end(), [](std::uint8_t value) {
        return value == kCanary;
    }));
    EXPECT_TRUE(std::all_of(shared_secret.begin(), shared_secret.end(), [](std::uint8_t value) {
        return value == kCanary;
    }));
}

}  // namespace
