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

/// @file iav_primula_test_support.hpp
/// @brief Test-only helpers for creating owned IAV-Primula native keys.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_TESTS_IAV_PRIMULA_TEST_SUPPORT_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_TESTS_IAV_PRIMULA_TEST_SUPPORT_HPP

#include "score/iav_primula/include/iav_primula_ffi.h"

#include <memory>

namespace score::crypto::daemon::provider::score_provider::iav_primula::test_support
{

/// @brief Destroy an IAV-Primula native key handle.
struct NativeKeyDeleter
{
    void operator()(iav_primula_key_handle* key) const noexcept;
};

/// @brief RAII owner for a valid IAV-Primula native key handle.
using NativeKey = std::unique_ptr<iav_primula_key_handle, NativeKeyDeleter>;

/// @brief Generate an ML-DSA key using the deterministic test-only RNG.
///
/// @param algorithm ML-DSA algorithm to generate.
/// @param key Receives ownership of the generated key on success.
/// @return The status from the registration or key-generation operation.
iav_status GenerateSignatureKey(iav_algorithm algorithm, NativeKey& key) noexcept;

/// @brief Generate an ML-KEM key using the deterministic test-only RNG.
///
/// @param algorithm ML-KEM algorithm to generate.
/// @param key Receives ownership of the generated key on success.
/// @return The status from the registration or key-generation operation.
iav_status GenerateKemKey(iav_algorithm algorithm, NativeKey& key) noexcept;

}  // namespace score::crypto::daemon::provider::score_provider::iav_primula::test_support

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_TESTS_IAV_PRIMULA_TEST_SUPPORT_HPP
