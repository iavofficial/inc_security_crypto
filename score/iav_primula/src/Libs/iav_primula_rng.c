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

/// @file iav_primula_rng.c
/// @brief One-time platform RNG registration and per-operation error tracking.

#include "iav_primula_rng_internal.h"

#include <limits.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "score/iav_primula/include/iav_primula_ffi.h"

enum
{
    IAV_RNG_UNREGISTERED = 0U,
    IAV_RNG_REGISTERING = 1U,
    IAV_RNG_READY = 2U
};

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables): immutable after one-time registration; atomics
// publish it.
static atomic_uint g_iav_rng_state = IAV_RNG_UNREGISTERED;
static iav_random_bytes_callback g_iav_rng_callback;
static void* g_iav_rng_user_data;
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables): per-thread operation error state is required by the
// vendor API.
static _Thread_local unsigned int g_iav_rng_operation_depth;
static _Thread_local bool g_iav_rng_operation_failed;
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

iav_status iav_random_bytes_provider_register(iav_random_bytes_callback callback, void* user_data)
{
    unsigned int expected_state = IAV_RNG_UNREGISTERED;

    if (callback == NULL)
    {
        return IavStatusInvalidArgument;
    }

    if (!atomic_compare_exchange_strong_explicit(
            &g_iav_rng_state, &expected_state, IAV_RNG_REGISTERING, memory_order_acq_rel, memory_order_acquire))
    {
        return IavStatusInvalidArgument;
    }

    g_iav_rng_callback = callback;
    g_iav_rng_user_data = user_data;
    atomic_store_explicit(&g_iav_rng_state, IAV_RNG_READY, memory_order_release);
    return IavStatusOk;
}

bool iav_primula_rng_operation_begin(void)
{
    if (atomic_load_explicit(&g_iav_rng_state, memory_order_acquire) != IAV_RNG_READY ||
        g_iav_rng_operation_depth == UINT_MAX)
    {
        return false;
    }

    if (g_iav_rng_operation_depth == 0U)
    {
        g_iav_rng_operation_failed = false;
    }

    ++g_iav_rng_operation_depth;
    return true;
}

bool iav_primula_rng_operation_end(void)
{
    if (g_iav_rng_operation_depth == 0U)
    {
        return false;
    }

    --g_iav_rng_operation_depth;
    return !g_iav_rng_operation_failed;
}

bool iav_primula_rng_get_bytes(unsigned char* output, size_t output_len)
{
    iav_random_bytes_callback callback = NULL;

    if (output_len == 0U)
    {
        return true;
    }

    if (output == NULL || atomic_load_explicit(&g_iav_rng_state, memory_order_acquire) != IAV_RNG_READY)
    {
        if (output != NULL)
        {
            iav_primula_secure_clear(output, output_len);
        }
        g_iav_rng_operation_failed = true;
        return false;
    }

    callback = g_iav_rng_callback;
    if (callback(output, output_len, g_iav_rng_user_data) != 0)
    {
        iav_primula_secure_clear(output, output_len);
        g_iav_rng_operation_failed = true;
        return false;
    }

    return true;
}

void iav_primula_secure_clear(void* memory, size_t length)
{
    volatile unsigned char* byte = (volatile unsigned char*)memory;

    if (memory == NULL)
    {
        return;
    }

    while (length > 0U)
    {
        *byte = 0U;
        ++byte;
        --length;
    }
}
