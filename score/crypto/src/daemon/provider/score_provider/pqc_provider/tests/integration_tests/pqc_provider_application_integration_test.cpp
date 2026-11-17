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

#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/sign_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/verify_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/factory/score_handler_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/key_management/pqc_provider_key_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/key_management/pqc_provider_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/operations/sign/pqc_provider_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/operations/verify/pqc_provider_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/pqc_provider.hpp"

#include <gtest/gtest.h>

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider;
using namespace score::crypto::daemon::provider::score_provider;
using namespace score::crypto::daemon::provider::score_provider::pqc_provider;

// ---------------------------------------------------------------------------
// SIGN handler creation and initialization
// ---------------------------------------------------------------------------

TEST(PqcProviderApplicationIntegrationTest, CreatesSignHandlerFromProviderToAlgorithm)
{
    // Initialize the provider with the test provider ID and provider name.
    PqcProviderProvider provider;
    ASSERT_TRUE(provider.Initialize(ProviderInitContext{common::ProviderId{7U}, "pqcProvider"}));

    // Create the provider-neutral factory and request an ML-DSA SIGN handler.
    auto factory = provider.GetCryptoHandlerFactory();
    ASSERT_NE(factory, nullptr);
    auto created = factory->CreateHandler("SIGN", *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44"));
    ASSERT_TRUE(created.has_value());
    auto handler = created.value();
    ASSERT_NE(handler, nullptr);
    auto* pqc_provider_handler = dynamic_cast<PqcProviderSignHandler*>(handler.get());
    ASSERT_NE(pqc_provider_handler, nullptr);
    EXPECT_EQ(pqc_provider_handler->GetAlgorithm().name, "ML-DSA-44");

    PqcProviderKeyFactory key_factory{provider.GetProviderId()};
    key_management::KeyGenerationRequest key_request{};
    key_request.algorithm = pqc_provider_handler->GetAlgorithm();
    auto generated = key_factory.GenerateKey(key_request);
    ASSERT_TRUE(generated.has_value());
    handler::InitializationParams params{};
    params.provider_id = provider.GetProviderId();
    params.bound_key_handler = generated.value().get();
    ASSERT_TRUE(handler->InitializeContext(params).has_value());
    EXPECT_EQ(pqc_provider_handler->GetOperationState(), common::StreamOperationState::IDLE);

    // Initialization without a bound key must be rejected.
    auto missing_key_initialization = handler->InitializeContext({});
    ASSERT_FALSE(missing_key_initialization.has_value());
    EXPECT_EQ(missing_key_initialization.error(), common::DaemonErrorCode::kInvalidArgument);
    provider.Shutdown();
}

// ---------------------------------------------------------------------------
// VERIFY handler creation and initialization
// ---------------------------------------------------------------------------

TEST(PqcProviderApplicationIntegrationTest, CreatesVerifyHandlerAndReachesAlgorithmValidation)
{
    // Initialize the provider before obtaining its handler factory.
    PqcProviderProvider provider;
    ASSERT_TRUE(provider.Initialize(ProviderInitContext{common::ProviderId{7U}, "pqcProvider"}));

    // Create a VERIFY handler for the ML-DSA-44 algorithm.
    auto created = provider.GetCryptoHandlerFactory()->CreateHandler(
        "VERIFY", *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44"));
    ASSERT_TRUE(created.has_value());
    auto handler = created.value();
    ASSERT_NE(handler, nullptr);
    auto* pqc_provider_handler = dynamic_cast<PqcProviderVerifyHandler*>(handler.get());
    ASSERT_NE(pqc_provider_handler, nullptr);
    EXPECT_EQ(pqc_provider_handler->GetAlgorithm().name, "ML-DSA-44");

    PqcProviderKeyFactory key_factory{provider.GetProviderId()};
    key_management::KeyGenerationRequest key_request{};
    key_request.algorithm = pqc_provider_handler->GetAlgorithm();
    auto generated = key_factory.GenerateKey(key_request);
    ASSERT_TRUE(generated.has_value());
    handler::InitializationParams params{};
    params.provider_id = provider.GetProviderId();
    params.bound_key_handler = generated.value().get();
    ASSERT_TRUE(handler->InitializeContext(params).has_value());
    EXPECT_EQ(pqc_provider_handler->GetOperationState(), common::StreamOperationState::IDLE);

    // A private-key descriptor without its native handle is incompatible.
    const auto key_handle = generated.value()->GetHandle();
    PqcProviderKeyHandler key_without_native_handle{nullptr, std::vector<std::uint8_t>(1312U), key_handle};
    params.bound_key_handler = &key_without_native_handle;
    auto incompatible_key_initialization = handler->InitializeContext(params);
    ASSERT_FALSE(incompatible_key_initialization.has_value());
    EXPECT_EQ(incompatible_key_initialization.error(), common::DaemonErrorCode::kIncompatibleKeyType);
    provider.Shutdown();
}
}  // namespace
