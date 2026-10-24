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

#ifndef SCORE_IAV_PRIMULA_TESTS_COMMON_TEST_HELPERS_H_
#define SCORE_IAV_PRIMULA_TESTS_COMMON_TEST_HELPERS_H_

#include <stddef.h>
#include <stdint.h>

#include <string>

uint8_t* hexStringToUint8Array(const std::string& hex, std::size_t& out_len);

#endif  // SCORE_IAV_PRIMULA_TESTS_COMMON_TEST_HELPERS_H_
