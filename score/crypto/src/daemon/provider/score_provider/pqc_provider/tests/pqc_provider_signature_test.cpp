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
#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/sign_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/key_management/pqc_provider_key_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/key_management/pqc_provider_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/operations/sign/pqc_provider_sign_handler.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <utility>
#include <vector>

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider::score_provider::pqc_provider;
using Executor = score::crypto::daemon::provider::score_provider::operations::sign::SignExecutor;
constexpr common::ProviderId kProviderId{7U};

key_management::ProviderKeyHandle SignatureHandle(
    const char* algorithm = "ML-DSA-44",
    key_management::KeyMaterialKind material_kind = key_management::KeyMaterialKind::kPrivateKey)
{
    key_management::ProviderKeyHandle handle{};
    handle.provider_id = kProviderId;
    handle.algorithm = *::score::crypto::GetAlgorithmDescriptor(algorithm);
    handle.is_asymmetric = true;
    handle.material_kind = material_kind;
    return handle;
}

// ---------------------------------------------------------------------------
// Signature algorithm sizes
// ---------------------------------------------------------------------------

TEST(PqcProviderSignatureTest, ReportsSupportedSizesAndRejectsKem)
{
    // Expected signature sizes for the supported ML-DSA variants.
    const std::pair<const char*, std::size_t> cases[] = {
        // ML-DSA-44: 2420 bytes, ML-DSA-65: 3309 bytes, ML-DSA-87: 4627 bytes.
        {"ML-DSA-44", 2420U},
        {"ML-DSA-65", 3309U},
        {"ML-DSA-87", 4627U}};
    for (const auto& test_case : cases)
    {
        PqcProviderSignHandler handler{std::make_unique<Executor>(),
                                       *::score::crypto::GetAlgorithmDescriptor(test_case.first)};
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
    PqcProviderSignHandler unsupported_handler{std::make_unique<Executor>(),
                                               *::score::crypto::GetAlgorithmDescriptor("ML-KEM-768")};
    EXPECT_EQ(unsupported_handler.GetSignatureSize(), 0U);
    auto result = unsupported_handler.InitializeContext({});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kUnsupportedAlgorithm);
}

// ---------------------------------------------------------------------------
// Output buffer validation
// ---------------------------------------------------------------------------

TEST(PqcProviderSignatureTest, ValidatesOutputBuffer)
{
    PqcProviderKeyFactory factory{kProviderId};
    key_management::KeyGenerationRequest request{};
    request.algorithm = *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44");
    auto generated = factory.GenerateKey(request);
    ASSERT_TRUE(generated.has_value());

    PqcProviderSignHandler handler{std::make_unique<Executor>(), *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = generated.value().get();
    ASSERT_TRUE(handler.InitializeContext(params).has_value());

    const std::uint8_t message[] = {1U, 2U};
    // ML-DSA-44 signatures require 2420 bytes; ten bytes are intentionally too small.
    std::vector<std::uint8_t> output(10U);
    const auto input = score::cpp::span<const std::uint8_t>{message, 2U};
    auto result = handler.SingleShotSign(input, score::cpp::span<std::uint8_t>{output.data(), output.size()});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInsufficientBufferSize);
}

// AC: AC-003
// Behavior: Bind a real ML-DSA-44 key generated through PQC Provider and successfully
// sign a message through the provider's single-shot operation.
// @lane: integration
// @dependency: PqcProviderKeyFactory and PqcProviderSignHandler.
// @real-dependency: Native PQC Provider ABI and liboqs ML-DSA-44 implementation.
// Primary failure mode: A valid provider key still fails to reach the native
// signing operation or does not produce a successful signature result.
// Proof obligation: Retain argument checks that fail before backend entry,
// replace the sentinel handle with a generated key, and assert successful
// signing with the provider's expected output size. Do not inject an artificial
// backend failure.
TEST(PqcProviderSignatureTest, ValidatesSingleShotRequestAndSignsGeneratedKey)
{
    namespace ops = provider::handler::sign_handler_operations;
    PqcProviderKeyFactory factory{kProviderId};
    key_management::KeyGenerationRequest key_request{};
    key_request.algorithm = *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44");
    auto generated = factory.GenerateKey(key_request);
    ASSERT_TRUE(generated.has_value());

    PqcProviderSignHandler handler{std::make_unique<Executor>(), *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
    provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = generated.value().get();
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
    auto signed_result = handler.Execute(operation, request);
    ASSERT_TRUE(signed_result.has_value());
    ASSERT_EQ(signed_result->size(), 1U);
    EXPECT_EQ(std::get<std::uint64_t>(signed_result->front()), handler.GetSignatureSize());
    EXPECT_EQ(handler.GetOperationState(), common::StreamOperationState::IDLE);

    auto wrong_actor = handler.Execute({common::actors::OP_ACTOR_VERIFY_HANDLER, ops::SIGN_SS}, request);
    ASSERT_FALSE(wrong_actor.has_value());
    EXPECT_EQ(wrong_actor.error(), common::DaemonErrorCode::kInvalidOperation);
}

TEST(PqcProviderSignatureTest, RequiresMatchingSignatureAlgorithm)
{
    PqcProviderKeyFactory factory{kProviderId};
    const char* signature_algorithms[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
    const char* key_algorithms[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
    for (const auto* algorithm : signature_algorithms)
    {
        const auto descriptor = *::score::crypto::GetAlgorithmDescriptor(algorithm);
        for (const auto* key_algorithm : key_algorithms)
        {
            SCOPED_TRACE(algorithm);
            SCOPED_TRACE(key_algorithm);
            PqcProviderSignHandler handler{std::make_unique<Executor>(), descriptor};
            const auto handle = SignatureHandle(key_algorithm);
            key_management::IKeyHandler::Sptr key;
            if (handle.algorithm.id == descriptor.id)
            {
                key_management::KeyGenerationRequest request{};
                request.algorithm = descriptor;
                auto generated = factory.GenerateKey(request);
                ASSERT_TRUE(generated.has_value());
                key = std::move(generated.value());
            }
            else
            {
                key = std::make_shared<PqcProviderKeyHandler>(nullptr, std::vector<std::uint8_t>{}, handle);
            }
            provider::handler::InitializationParams params{};
            params.provider_id = kProviderId;
            params.bound_key_handler = key.get();

            const auto result = handler.InitializeContext(params);
            if (handle.algorithm.id == descriptor.id)
            {
                EXPECT_TRUE(result.has_value());
            }
            else
            {
                ASSERT_FALSE(result.has_value());
                EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);
            }
        }
    }
}

TEST(PqcProviderSignatureTest, RejectsNonPrivateSignatureMaterial)
{
    using key_management::KeyMaterialKind;
    const KeyMaterialKind kinds[] = {KeyMaterialKind::kUnspecified,
                                     KeyMaterialKind::kPublicKey,
                                     KeyMaterialKind::kSymmetricKey,
                                     KeyMaterialKind::kSharedSecret};
    for (const auto kind : kinds)
    {
        SCOPED_TRACE(static_cast<int>(kind));
        PqcProviderSignHandler handler{std::make_unique<Executor>(),
                                       *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
        PqcProviderKeyHandler key{nullptr, {}, SignatureHandle("ML-DSA-44", kind)};
        provider::handler::InitializationParams params{};
        params.provider_id = kProviderId;
        params.bound_key_handler = &key;

        const auto result = handler.InitializeContext(params);
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);
    }
}

TEST(PqcProviderSignatureTest, RejectsMissingNativeHandleAndClearsKeyAfterFailedRebind)
{
    PqcProviderKeyFactory factory{kProviderId};
    key_management::KeyGenerationRequest request{};
    request.algorithm = *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44");
    auto generated = factory.GenerateKey(request);
    ASSERT_TRUE(generated.has_value());

    PqcProviderSignHandler handler{std::make_unique<Executor>(), *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
    provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = generated.value().get();
    ASSERT_TRUE(handler.InitializeContext(params).has_value());

    PqcProviderKeyHandler missing_native_key{nullptr, {}, SignatureHandle()};
    params.bound_key_handler = &missing_native_key;
    const auto result = handler.InitializeContext(params);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);

    const auto sign = handler.SingleShotSign({}, {});
    ASSERT_FALSE(sign.has_value());
    EXPECT_EQ(sign.error(), common::DaemonErrorCode::kKeySlotEmpty);
}
}  // namespace
