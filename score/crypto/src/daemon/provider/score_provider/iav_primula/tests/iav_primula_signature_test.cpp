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

#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"
#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/sign_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/sign/iav_primula_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/tests/iav_primula_test_support.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"
#include "score/iav_primula/include/iav_primula_ffi.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "score/span.hpp"

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider::score_provider::iav_primula;
using Executor = score::crypto::daemon::provider::score_provider::operations::sign::SignExecutor;
namespace test_support = score::crypto::daemon::provider::score_provider::iav_primula::test_support;
constexpr common::ProviderId kProviderId{7U};

// ---------------------------------------------------------------------------
// Signature algorithm sizes
// ---------------------------------------------------------------------------

TEST(IavPrimulaSignatureTest, ReportsSupportedSizesAndRejectsKem)
{
    // Expected signature sizes for the supported ML-DSA variants.
    const std::pair<const char*, std::size_t> cases[] = {
        // ML-DSA-44: 2420 bytes, ML-DSA-65: 3309 bytes, ML-DSA-87: 4627 bytes.
        {"ML-DSA-44", 2420U},
        {"ML-DSA-65", 3309U},
        {"ML-DSA-87", 4627U}};
    for (const auto& test_case : cases)
    {
        IavPrimulaSignHandler handler{std::make_unique<Executor>(), test_case.first};
        EXPECT_EQ(handler.GetSignatureSize(), test_case.second);
        common::RequestParameters request;
        auto result = handler.Execute(
            {common::actors::OP_ACTOR_SIGN_HANDLER, provider::handler::sign_handler_operations::SIGN_GET_SIZE},
            request);
        ASSERT_TRUE(result.has_value());
        ASSERT_EQ(result->size(), 1U);
        EXPECT_EQ(std::get<std::uint64_t>(result->front()), test_case.second);
    }

    // A KEM algorithm is not a supported signature algorithm.
    IavPrimulaSignHandler unsupported_handler{std::make_unique<Executor>(), "ML-KEM-768"};
    EXPECT_EQ(unsupported_handler.GetSignatureSize(), 0U);
    auto result = unsupported_handler.InitializeContext({});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kUnsupportedAlgorithm);
}

// ---------------------------------------------------------------------------
// Output buffer validation
// ---------------------------------------------------------------------------

TEST(IavPrimulaSignatureTest, ValidatesOutputBuffer)
{
    IavPrimulaSignHandler handler{std::make_unique<Executor>(), "ML-DSA-44"};
    key_management::ProviderKeyHandle key_handle{};
    key_handle.provider_id = kProviderId;
    test_support::NativeKey native_key;
    ASSERT_EQ(test_support::GenerateSignatureKey(IavAlgorithmMlDsa44, native_key), IavStatusOk);
    IavPrimulaKeyHandler key{native_key.release(), {}, key_handle};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());

    const std::uint8_t message[] = {1U, 2U};
    // ML-DSA-44 signatures require 2420 bytes; ten bytes are intentionally too small.
    std::vector<std::uint8_t> output(10U);
    const auto input = score::cpp::span<const std::uint8_t>{message, 2U};
    auto result = handler.SingleShotSign(input, score::cpp::span<std::uint8_t>{output.data(), output.size()});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInsufficientBufferSize);
}

TEST(IavPrimulaSignatureTest, ValidatesSingleShotRequestAndPropagatesBackendFailure)
{
    namespace ops = provider::handler::sign_handler_operations;
    IavPrimulaSignHandler handler{std::make_unique<Executor>(), "ML-DSA-44"};
    key_management::ProviderKeyHandle key_handle{};
    key_handle.provider_id = kProviderId;
    // A valid ML-KEM key is deliberately bound to the ML-DSA handler so the
    // backend safely reports an incompatible key family.
    test_support::NativeKey native_key;
    ASSERT_EQ(test_support::GenerateKemKey(IavAlgorithmMlKem768, native_key), IavStatusOk);
    IavPrimulaKeyHandler key{native_key.release(), {}, key_handle};
    provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    const std::uint8_t message[] = {1U, 2U};
    const auto input = score::cpp::span<const std::uint8_t>{message, 2U};
    common::RequestParameters request{input};
    const common::OperationIdentifier operation{common::actors::OP_ACTOR_SIGN_HANDLER, ops::SIGN_SS};
    auto missing = handler.Execute(operation, request);
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error(), common::DaemonErrorCode::kInsufficientParameters);

    request.emplace_back(std::uint64_t{0U});
    auto wrong_type = handler.Execute(operation, request);
    ASSERT_FALSE(wrong_type.has_value());
    EXPECT_EQ(wrong_type.error(), common::DaemonErrorCode::kInvalidDataType);

    std::vector<std::uint8_t> output(handler.GetSignatureSize());
    request[1] = score::cpp::span<std::uint8_t>{output.data(), output.size()};
    auto backend = handler.Execute(operation, request);
    ASSERT_FALSE(backend.has_value());
    EXPECT_EQ(backend.error(), common::DaemonErrorCode::kAlgorithmExecutionFailed);
    EXPECT_EQ(handler.GetOperationState(), common::StreamOperationState::IDLE);

    auto wrong_actor = handler.Execute({common::actors::OP_ACTOR_VERIFY_HANDLER, ops::SIGN_SS}, request);
    ASSERT_FALSE(wrong_actor.has_value());
    EXPECT_EQ(wrong_actor.error(), common::DaemonErrorCode::kInvalidOperation);
}
}  // namespace
