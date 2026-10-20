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

#include "score/crypto/src/daemon/provider/score_provider/iav_primula/tests/iav_primula_test_support.hpp"
#include "score/iav_primula/include/iav_primula_ffi.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace score::crypto::daemon::provider::score_provider::iav_primula::test_support
{
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

/// @brief Fill requested bytes with deterministic test-only data.
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

iav_status RegisterTestRandomBytesProvider() noexcept
{
    static TestRngContext context;
    static const iav_status status = iav_random_bytes_provider_register(FillTestRandomBytes, &context);
    return status;
}

}  // namespace

void NativeKeyDeleter::operator()(iav_primula_key_handle* key) const noexcept
{
    iav_key_destroy(key);
}

iav_status GenerateSignatureKey(iav_algorithm algorithm, NativeKey& key) noexcept
{
    key.reset();
    const iav_status registration_status = RegisterTestRandomBytesProvider();
    if (registration_status != IavStatusOk)
    {
        return registration_status;
    }

    iav_primula_key_handle* native_key = nullptr;
    const iav_status status = iav_keypair_generate(algorithm, &native_key);
    key.reset(native_key);
    return status;
}

iav_status GenerateKemKey(iav_algorithm algorithm, NativeKey& key) noexcept
{
    key.reset();
    const iav_status registration_status = RegisterTestRandomBytesProvider();
    if (registration_status != IavStatusOk)
    {
        return registration_status;
    }

    iav_primula_key_handle* native_key = nullptr;
    const iav_status status = iav_kem_keypair_generate(algorithm, &native_key);
    key.reset(native_key);
    return status;
}

}  // namespace score::crypto::daemon::provider::score_provider::iav_primula::test_support
