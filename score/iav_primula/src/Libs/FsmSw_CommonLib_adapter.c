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

/// @file FsmSw_CommonLib_adapter.c
/// @brief Project-owned CommonLib replacements with no deterministic RNG.

#include "FsmSw_CommonLib.h"

#include <stddef.h>
#include <stdint.h>

#include "iav_primula_rng_internal.h"
#include "score/iav_primula/include/Platform_Types.h"

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): vendor ABI signature is fixed.
void FsmSw_CommonLib_MemCpy(void* const dest, const void* const src, const uint32 n)
{
    uint8* const dest_bytes = (uint8*)dest;
    const uint8* const src_bytes = (const uint8*)src;
    size_t index = 0U;

    for (index = 0U; index < (size_t)n; ++index)
    {
        dest_bytes[index] = src_bytes[index];
    }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): vendor ABI signature is fixed.
void FsmSw_CommonLib_MemSet(void* const dest, const uint8 value, const uint32 n)
{
    uint8* const dest_bytes = (uint8*)dest;
    size_t index = 0U;

    for (index = 0U; index < (size_t)n; ++index)
    {
        dest_bytes[index] = value;
    }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): vendor ABI signature is fixed.
uint8 FsmSw_CommonLib_MemCmp(void* const dest, const void* const src, const uint32 n)
{
    const uint8* const dest_bytes = (const uint8*)dest;
    const uint8* const src_bytes = (const uint8*)src;
    uint32 index = 0U;

    for (index = 0U; index < n; ++index)
    {
        if (dest_bytes[index] != src_bytes[index])
        {
            return 1U;
        }
    }

    return 0U;
}

void FsmSw_CommonLib_MemMove(void* const dest, const void* const src, const uint32 n)
{
    uint8* const dest_bytes = (uint8*)dest;
    const uint8* const src_bytes = (const uint8*)src;
    uint32 index = 0U;

    if ((uintptr_t)dest <= (uintptr_t)src)
    {
        for (index = 0U; index < n; ++index)
        {
            dest_bytes[index] = src_bytes[index];
        }
    }
    else
    {
        for (index = n; index > 0U; --index)
        {
            dest_bytes[index - 1U] = src_bytes[index - 1U];
        }
    }
}

uint8 FsmSw_CommonLib_RandomBytes(uint8* const output, const uint32 n)
{
    return iav_primula_rng_get_bytes(output, (size_t)n) ? ERR_OK : ERR_NOT_OK;
}

void FsmSw_CommonLib_SRand(const uint32 seed)
{
    // Kept only for source compatibility; the platform RNG is not seedable here.
    (void)seed;
}
