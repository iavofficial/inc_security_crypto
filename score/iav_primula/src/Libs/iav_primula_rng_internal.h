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

/// @file iav_primula_rng_internal.h
/// @brief Private helpers for the Automotive random-byte boundary.

#ifndef SCORE_IAV_PRIMULA_RNG_INTERNAL_H
#define SCORE_IAV_PRIMULA_RNG_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

/// @brief Begin tracking entropy-provider errors for the current operation.
///
/// @return true if a provider is installed and the operation can proceed.
bool iav_primula_rng_operation_begin(void);

/// @brief End tracking and report whether all entropy requests succeeded.
///
/// @return true if no random-byte request failed during the operation.
bool iav_primula_rng_operation_end(void);

/// @brief Request random bytes from the registered platform provider.
bool iav_primula_rng_get_bytes(unsigned char* output, size_t output_len);

/// @brief Clear memory using writes that are not removed as dead stores.
void iav_primula_secure_clear(void* memory, size_t length);

#endif  // SCORE_IAV_PRIMULA_RNG_INTERNAL_H
