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

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/kem_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/kem/iav_primula_kem_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/tests/iav_primula_test_support.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/kem/kem_executor.hpp"
#include "score/iav_primula/include/iav_primula_ffi.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <variant>
#include <vector>

#include "score/span.hpp"

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider::score_provider::iav_primula;
using Executor = score::crypto::daemon::provider::score_provider::operations::kem::KemExecutor;
namespace test_support = score::crypto::daemon::provider::score_provider::iav_primula::test_support;

// ---------------------------------------------------------------------------
// Algorithm and input validation
// ---------------------------------------------------------------------------

TEST(IavPrimulaKemTest, RejectsInvalidEncapsulationInput)
{
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    const std::uint8_t public_key[] = {1U, 2U};
    auto result = handler.Encapsulate(score::cpp::span<const std::uint8_t>{public_key, sizeof(public_key)});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

TEST(IavPrimulaKemTest, RequiresBoundKeyForDecapsulation)
{
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    const std::uint8_t ciphertext[] = {1U, 2U};
    auto result = handler.Decapsulate(score::cpp::span<const std::uint8_t>{ciphertext, sizeof(ciphertext)});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// Backend status propagation
// ---------------------------------------------------------------------------

TEST(IavPrimulaKemTest, PropagatesBackendStatusForValidEncapsulation)
{
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    // ML-KEM-768 public keys contain 1184 bytes.
    const std::vector<std::uint8_t> public_key(1184U, 0U);
    auto result = handler.Encapsulate(score::cpp::span<const std::uint8_t>{public_key.data(), public_key.size()});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kOperationFailed);
}

TEST(IavPrimulaKemTest, DecapsulatesInvalidCiphertextUsingImplicitRejection)
{
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    test_support::NativeKey native_key;
    ASSERT_EQ(test_support::GenerateKemKey(IavAlgorithmMlKem768, native_key), IavStatusOk);
    IavPrimulaKeyHandler key{native_key.release(), {}, {}};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    // ML-KEM invalid ciphertexts have an implicit-rejection secret.
    const std::vector<std::uint8_t> ciphertext(1088U, 0U);
    auto result = handler.Decapsulate(score::cpp::span<const std::uint8_t>{ciphertext.data(), ciphertext.size()});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1U);
    const auto* secret = std::get_if<common::OwnedBuffer>(&result->front());
    ASSERT_NE(secret, nullptr);
    constexpr std::size_t kSharedSecretSize = 32U;
    EXPECT_EQ(secret->size(), kSharedSecretSize);
}

// ---------------------------------------------------------------------------
// Handler dispatch and context management
// ---------------------------------------------------------------------------

TEST(IavPrimulaKemTest, DispatchesOperationsAndReset)
{
    // Verify that the handler dispatches a KEM operation and RESET.
    using namespace score::crypto::daemon::provider::handler::kem_handler_operations;
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    common::OperationIdentifier unsupported{0U, 1U};
    common::RequestParameters no_parameters{};
    auto unsupported_result = handler.Execute(unsupported, no_parameters);
    ASSERT_FALSE(unsupported_result.has_value());
    EXPECT_EQ(unsupported_result.error(), common::DaemonErrorCode::kInvalidOperation);
    common::OperationIdentifier reset{0U, KEM_RESET};
    auto reset_result = handler.Execute(reset, no_parameters);
    ASSERT_TRUE(reset_result.has_value());
    EXPECT_TRUE(reset_result->empty());
}

TEST(IavPrimulaKemTest, AllowsContextWithoutBoundKey)
{
    IavPrimulaKemHandler handler{std::make_unique<Executor>(), "ML-KEM-768"};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    // Context initialization is allowed without a bound key; decapsulation
    // validates that a key is available when the operation is executed.
    EXPECT_TRUE(handler.InitializeContext(params).has_value());
}
}  // namespace
