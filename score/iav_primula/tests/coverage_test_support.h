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

#ifndef SCORE_IAV_PRIMULA_TESTS_COVERAGE_TEST_SUPPORT_H
#define SCORE_IAV_PRIMULA_TESTS_COVERAGE_TEST_SUPPORT_H

#include "score/iav_primula/include/iav_primula_ffi.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace iav_primula_test
{

struct DeterministicRngContext
{
    std::atomic<std::uint64_t> request_counter{0U};
};

constexpr std::uint64_t kSplitMixGamma = 0x9E3779B97F4A7C15ULL;
constexpr std::uint64_t kSplitMixMultiplier1 = 0xBF58476D1CE4E5B9ULL;
constexpr std::uint64_t kSplitMixMultiplier2 = 0x94D049BB133111EBULL;

/// Deterministic test provider; production targets never depend on this helper.
inline int FillDeterministicRandomBytes(std::uint8_t* output, std::size_t output_len, void* user_data)
{
    auto* const context = static_cast<DeterministicRngContext*>(user_data);
    if (context == nullptr || (output == nullptr && output_len != 0U))
    {
        return 1;
    }

    constexpr unsigned int kShift1 = 30U;
    constexpr unsigned int kShift2 = 27U;
    constexpr unsigned int kShift3 = 31U;
    constexpr unsigned int kOutputByteShift = 56U;
    const std::uint64_t request = context->request_counter.fetch_add(1U, std::memory_order_relaxed);

    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic): fill the callback's caller-provided byte span.
    for (std::size_t index = 0U; index < output_len; ++index)
    {
        std::uint64_t value = request + kSplitMixGamma * (index + 1U);
        value = (value ^ (value >> kShift1)) * kSplitMixMultiplier1;
        value = (value ^ (value >> kShift2)) * kSplitMixMultiplier2;
        value ^= value >> kShift3;
        output[index] = static_cast<std::uint8_t>(value >> kOutputByteShift);
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return 0;
}

inline iav_status RegisterDeterministicRandomProvider()
{
    static DeterministicRngContext context;
    static const iav_status status = iav_random_bytes_provider_register(FillDeterministicRandomBytes, &context);
    return status;
}

}  // namespace iav_primula_test

#endif  // SCORE_IAV_PRIMULA_TESTS_COVERAGE_TEST_SUPPORT_H
