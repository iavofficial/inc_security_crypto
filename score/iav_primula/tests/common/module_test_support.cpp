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

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>

#include "module_test_support.h"
#include "score/iav_primula/include/iav_primula_ffi.h"

namespace
{

struct ModuleTestRngState
{
    std::uint32_t next = 1U;
};

const std::uint8_t* rng_override_bytes = nullptr;
std::size_t rng_override_len = 0U;
std::size_t rng_override_offset = 0U;

int FillReferenceRngBytes(std::uint8_t* output, std::size_t output_len, void* user_data)
{
    if (user_data == nullptr || (output == nullptr && output_len != 0U))
    {
        return 1;
    }

    if (rng_override_bytes != nullptr)
    {
        for (std::size_t index = 0U; index < output_len; ++index)
        {
            output[index] = rng_override_offset < rng_override_len ? rng_override_bytes[rng_override_offset++] : 0U;
        }
        return 0;
    }

    auto* const state = static_cast<ModuleTestRngState*>(user_data);
    for (std::size_t index = 0U; index < output_len; ++index)
    {
        state->next = (state->next * 1103515245U) + 12345U;
        const std::uint32_t value = (state->next / 65536U) & 32767U;
        output[index] = static_cast<std::uint8_t>(value / 128U);
    }
    return 0;
}

class ModuleTestRngEnvironment final : public ::testing::Environment
{
  public:
    void SetUp() override
    {
        EXPECT_EQ(iav_random_bytes_provider_register(FillReferenceRngBytes, &state_), IavStatusOk);
    }

  private:
    ModuleTestRngState state_{};
};

::testing::Environment* const kModuleTestRngEnvironment =
    ::testing::AddGlobalTestEnvironment(new ModuleTestRngEnvironment());

}  // namespace

ModuleTestRngOverride::ModuleTestRngOverride(const uint8_t* seed, size_t seed_len)
{
    rng_override_bytes = seed;
    rng_override_len = seed_len;
    rng_override_offset = 0U;
}

ModuleTestRngOverride::~ModuleTestRngOverride()
{
    rng_override_bytes = nullptr;
    rng_override_len = 0U;
    rng_override_offset = 0U;
}
