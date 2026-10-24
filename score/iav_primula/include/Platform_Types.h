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

/// @file Platform_Types.h
/// @brief Fixed-width platform aliases required by PQCleanAutomotive.

#ifndef SCORE_IAV_PRIMULA_PLATFORM_TYPES_H
#define SCORE_IAV_PRIMULA_PLATFORM_TYPES_H

#include <stdint.h>

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

typedef int8_t sint8;
typedef int16_t sint16;
typedef int32_t sint32;
typedef int64_t sint64;

typedef float float32;

#if defined(__cplusplus)
static_assert(sizeof(uint8) == 1U, "uint8 must be 8 bits");
static_assert(sizeof(uint16) == 2U, "uint16 must be 16 bits");
static_assert(sizeof(uint32) == 4U, "uint32 must be 32 bits");
static_assert(sizeof(uint64) == sizeof(uint32) * 2U, "uint64 must be 64 bits");
static_assert(sizeof(sint8) == 1U, "sint8 must be 8 bits");
static_assert(sizeof(sint16) == 2U, "sint16 must be 16 bits");
static_assert(sizeof(sint32) == 4U, "sint32 must be 32 bits");
static_assert(sizeof(sint64) == sizeof(sint32) * 2U, "sint64 must be 64 bits");
static_assert(sizeof(float32) == 4U, "float32 must be 32 bits");
#else
_Static_assert(sizeof(uint8) == 1U, "uint8 must be 8 bits");
_Static_assert(sizeof(uint16) == 2U, "uint16 must be 16 bits");
_Static_assert(sizeof(uint32) == 4U, "uint32 must be 32 bits");
_Static_assert(sizeof(uint64) == sizeof(uint32) * 2U, "uint64 must be 64 bits");
_Static_assert(sizeof(sint8) == 1U, "sint8 must be 8 bits");
_Static_assert(sizeof(sint16) == 2U, "sint16 must be 16 bits");
_Static_assert(sizeof(sint32) == 4U, "sint32 must be 32 bits");
_Static_assert(sizeof(sint64) == sizeof(sint32) * 2U, "sint64 must be 64 bits");
_Static_assert(sizeof(float32) == 4U, "float32 must be 32 bits");
#endif

#endif  // SCORE_IAV_PRIMULA_PLATFORM_TYPES_H
