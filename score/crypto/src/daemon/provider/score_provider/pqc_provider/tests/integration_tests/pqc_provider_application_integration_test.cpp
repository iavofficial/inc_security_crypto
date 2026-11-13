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
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/pqc_provider.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/key_management/pqc_provider_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/operations/sign/pqc_provider_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/operations/verify/pqc_provider_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/factory/score_handler_factory.hpp"

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
    PqcProvider provider;
    ASSERT_TRUE(provider.Initialize(ProviderInitContext{common::ProviderId{7U}, "pqc_provider"}));

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

    // Use a non-null sentinel to simulate a bound native key handle without
    // creating a real backend key.
    key_management::ProviderKeyHandle key_handle{};
    key_handle.provider_id = provider.GetProviderId();
    key_handle.algorithm = pqc_provider_handler->GetAlgorithm();
    key_handle.is_asymmetric = true;
    key_handle.material_kind = key_management::KeyMaterialKind::kPrivateKey;
    PqcProviderKeyHandler key{reinterpret_cast<pqc_provider_key_handle*>(0x1), {}, key_handle};
    handler::InitializationParams params{};
    params.provider_id = provider.GetProviderId();
    params.bound_key_handler = &key;
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
    PqcProvider provider;
    ASSERT_TRUE(provider.Initialize(ProviderInitContext{common::ProviderId{7U}, "pqc_provider"}));

    // Create a VERIFY handler for the ML-DSA-44 algorithm.
    auto created = provider.GetCryptoHandlerFactory()->CreateHandler("VERIFY", *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44"));
    ASSERT_TRUE(created.has_value());
    auto handler = created.value();
    ASSERT_NE(handler, nullptr);
    auto* pqc_provider_handler = dynamic_cast<PqcProviderVerifyHandler*>(handler.get());
    ASSERT_NE(pqc_provider_handler, nullptr);
    EXPECT_EQ(pqc_provider_handler->GetAlgorithm().name, "ML-DSA-44");

    // A non-null sentinel represents a bound native key handle for initialization.
    key_management::ProviderKeyHandle key_handle{};
    key_handle.provider_id = provider.GetProviderId();
    key_handle.algorithm = pqc_provider_handler->GetAlgorithm();
    key_handle.is_asymmetric = true;
    key_handle.material_kind = key_management::KeyMaterialKind::kPrivateKey;
    PqcProviderKeyHandler key{reinterpret_cast<pqc_provider_key_handle*>(0x1), {}, key_handle};
    handler::InitializationParams params{};
    params.provider_id = provider.GetProviderId();
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler->InitializeContext(params).has_value());
    EXPECT_EQ(pqc_provider_handler->GetOperationState(), common::StreamOperationState::IDLE);

    // Public-only key material has no native handle and is incompatible with
    // the native-key-based verification implementation.
    PqcProviderKeyHandler public_only_key{nullptr, std::vector<std::uint8_t>(1312U), key_handle};
    params.bound_key_handler = &public_only_key;
    auto incompatible_key_initialization = handler->InitializeContext(params);
    ASSERT_FALSE(incompatible_key_initialization.has_value());
    EXPECT_EQ(incompatible_key_initialization.error(), common::DaemonErrorCode::kIncompatibleKeyType);
    provider.Shutdown();
}
}  // namespace
