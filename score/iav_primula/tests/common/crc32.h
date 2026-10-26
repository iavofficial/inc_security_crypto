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

#ifndef SCORE_IAV_PRIMULA_TESTS_CRC32_H
#define SCORE_IAV_PRIMULA_TESTS_CRC32_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t crc32(const void* buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif  // SCORE_IAV_PRIMULA_TESTS_CRC32_H
