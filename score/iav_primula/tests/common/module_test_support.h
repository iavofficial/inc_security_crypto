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

#ifndef SCORE_IAV_PRIMULA_TESTS_COMMON_MODULE_TEST_SUPPORT_H_
#define SCORE_IAV_PRIMULA_TESTS_COMMON_MODULE_TEST_SUPPORT_H_

#include <stddef.h>
#include <stdint.h>

// Temporarily route the module test RNG provider to a supplied byte sequence.
// Remaining requested bytes are zero-filled, matching the upstream smoke stubs.
class ModuleTestRngOverride final
{
  public:
    ModuleTestRngOverride(const uint8_t* seed, size_t seed_len);
    ~ModuleTestRngOverride();

    ModuleTestRngOverride(const ModuleTestRngOverride&) = delete;
    ModuleTestRngOverride& operator=(const ModuleTestRngOverride&) = delete;
};

#endif  // SCORE_IAV_PRIMULA_TESTS_COMMON_MODULE_TEST_SUPPORT_H_
