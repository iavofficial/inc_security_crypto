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
#include "score/crypto/src/daemon/common/actors.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/verify_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/key_management/pqc_provider_key_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/key_management/pqc_provider_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/operations/verify/pqc_provider_verify_handler.hpp"
#include "score/pqc_provider/include/pqc_provider_ffi.h"

#include <gtest/gtest.h>

#include <vector>

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider::score_provider::pqc_provider;
using Executor = score::crypto::daemon::provider::score_provider::operations::verify::VerifyExecutor;

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
// Algorithm and key validation
// ---------------------------------------------------------------------------

TEST(PqcProviderVerificationTest, RejectsUnsupportedAndMissingKeys)
{
    // ML-KEM-768 is not a supported signature-verification algorithm.
    PqcProviderVerifyHandler unsupported_handler{std::make_unique<Executor>(),
                                                 *::score::crypto::GetAlgorithmDescriptor("ML-KEM-768")};
    auto unsupported_result = unsupported_handler.InitializeContext({});
    ASSERT_FALSE(unsupported_result.has_value());
    EXPECT_EQ(unsupported_result.error(), common::DaemonErrorCode::kUnsupportedAlgorithm);

    // ML-DSA-44 requires a bound verification key during initialization.
    PqcProviderVerifyHandler handler{std::make_unique<Executor>(),
                                     *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    auto result = handler.InitializeContext(params);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

TEST(PqcProviderVerificationTest, RejectsUnassignedProviderId)
{
    PqcProviderVerifyHandler handler{std::make_unique<Executor>(),
                                     *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
    // Both IDs default to invalid; matching invalid IDs must not authorize a cast.
    PqcProviderKeyHandler key{nullptr, {}, {}};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.bound_key_handler = &key;

    auto result = handler.InitializeContext(params);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

TEST(PqcProviderVerificationTest, RejectsKeyFromAnotherProvider)
{
    PqcProviderVerifyHandler handler{std::make_unique<Executor>(),
                                     *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
    const auto handle = SignatureHandle();
    PqcProviderKeyHandler key{nullptr, {}, handle};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.provider_id = common::ProviderId{8U};
    params.bound_key_handler = &key;

    auto result = handler.InitializeContext(params);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// Signature input validation
// ---------------------------------------------------------------------------

TEST(PqcProviderVerificationTest, ValidatesKeyTypeAndSignatureSize)
{
    PqcProviderVerifyHandler handler{std::make_unique<Executor>(),
                                     *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
    // A public-only key must contain the expected number of public-key bytes.
    PqcProviderKeyHandler public_key{nullptr,
                                     std::vector<std::uint8_t>(1311U),
                                     SignatureHandle("ML-DSA-44", key_management::KeyMaterialKind::kPublicKey)};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = &public_key;
    auto result = handler.InitializeContext(params);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);

    PqcProviderKeyFactory factory{kProviderId};
    key_management::KeyGenerationRequest request{};
    request.algorithm = *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44");
    auto generated = factory.GenerateKey(request);
    ASSERT_TRUE(generated.has_value());
    params.bound_key_handler = generated.value().get();
    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    const std::uint8_t message[] = {1U, 2U};
    // ML-DSA-44 signatures are 2420 bytes; ten bytes are intentionally invalid.
    std::vector<std::uint8_t> signature(10U);
    const auto input = score::cpp::span<const std::uint8_t>{message, 2U};
    auto verify =
        handler.SingleShotVerify(input, score::cpp::span<const std::uint8_t>{signature.data(), signature.size()});
    ASSERT_FALSE(verify.has_value());
    EXPECT_EQ(verify.error(), common::DaemonErrorCode::kInvalidArgument);
}

// AC: AC-003
// Behavior: Use an ML-DSA-44 key generated through PQC Provider and its pqc_provider_sign
// operation to produce a valid signature; provider verification succeeds with
// both its generated handle and an imported copy of its exported public bytes,
// while a modified signature returns false rather than an execution error.
// @lane: integration
// @dependency: PqcProviderKeyFactory, public-key import, and
// PqcProviderVerifyHandler.
// @real-dependency: Native PQC Provider ABI and liboqs ML-DSA-44 implementation.
// Primary failure mode: Provider verification fails for a valid generated or
// imported key, or maps an invalid signature to an execution error.
// Proof obligation: Replace dummy key/signature bytes with a generated key and
// valid signature; assert true for generated-handle and imported-key
// verification, then false for an invalid signature. Keep this as one
// representative provider variant; the ABI test owns six-variant coverage.
TEST(PqcProviderVerificationTest, VerifiesGeneratedAndImportedKeysAndRejectsInvalidSignature)
{
    using Permission = score::crypto::KeyOperationPermission;
    PqcProviderKeyFactory factory{kProviderId};
    const auto descriptor = *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44");
    key_management::KeyGenerationRequest generation_request{};
    generation_request.algorithm = descriptor;
    generation_request.permissions = Permission::kSign;
    generation_request.public_key_permissions = Permission::kExport;
    auto generated = factory.GenerateKey(generation_request);
    ASSERT_TRUE(generated.has_value());

    auto* const generated_key = static_cast<PqcProviderKeyHandler*>(generated.value().get());
    const auto exported_public_key = generated_key->Export();
    ASSERT_TRUE(exported_public_key.has_value());
    ASSERT_EQ(exported_public_key->bytes.size(), descriptor.public_key_size);

    const std::uint8_t message[] = {1U, 2U};
    std::vector<std::uint8_t> signature(2420U);
    std::size_t signature_length = signature.size();
    ASSERT_EQ(pqc_provider_sign(generated_key->GetNativeHandle(), message, sizeof(message), signature.data(), &signature_length),
              PqcProviderStatusOk);
    ASSERT_EQ(signature_length, signature.size());

    PqcProviderVerifyHandler handler{std::make_unique<Executor>(), descriptor};
    provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = generated.value().get();
    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    const auto generated_result =
        handler.SingleShotVerify({message, sizeof(message)}, {signature.data(), signature.size()});
    ASSERT_TRUE(generated_result.has_value());
    EXPECT_TRUE(generated_result.value());

    key_management::KeyImportRequest import_request{};
    import_request.algorithm = descriptor;
    import_request.format = score::crypto::FormatType::kRaw;
    import_request.permissions = Permission::kVerify;
    import_request.key_data = exported_public_key->bytes.data();
    import_request.key_data_size = exported_public_key->bytes.size();
    auto imported = factory.ImportKey(import_request);
    ASSERT_TRUE(imported.has_value());

    params.bound_key_handler = imported.value().get();
    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    const auto imported_result =
        handler.SingleShotVerify({message, sizeof(message)}, {signature.data(), signature.size()});
    ASSERT_TRUE(imported_result.has_value());
    EXPECT_TRUE(imported_result.value());

    signature.front() ^= 0x01U;
    const auto invalid_result =
        handler.SingleShotVerify({message, sizeof(message)}, {signature.data(), signature.size()});
    ASSERT_TRUE(invalid_result.has_value());
    EXPECT_FALSE(invalid_result.value());
}

TEST(PqcProviderVerificationTest, RejectsReleasedPublicKey)
{
    const auto descriptor = *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44");
    PqcProviderKeyHandler key{nullptr,
                              std::vector<std::uint8_t>(descriptor.public_key_size),
                              SignatureHandle("ML-DSA-44", key_management::KeyMaterialKind::kPublicKey)};
    PqcProviderVerifyHandler handler{std::make_unique<Executor>(), descriptor};
    provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    ASSERT_TRUE(key.Release().has_value());

    const std::vector<std::uint8_t> signature(handler.GetSignatureSize());
    const auto result = handler.SingleShotVerify({}, {signature.data(), signature.size()});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kKeySlotEmpty);

    const auto rebind = handler.InitializeContext(params);
    ASSERT_FALSE(rebind.has_value());
    EXPECT_EQ(rebind.error(), common::DaemonErrorCode::kIncompatibleKeyType);
}

TEST(PqcProviderVerificationTest, RejectsSingleShotRequestWithoutSignature)
{
    PqcProviderVerifyHandler handler{std::make_unique<Executor>(),
                                     *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
    PqcProviderKeyHandler key{nullptr,
                              std::vector<std::uint8_t>(1312U),
                              SignatureHandle("ML-DSA-44", key_management::KeyMaterialKind::kPublicKey)};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());

    const std::uint8_t message[] = {1U, 2U};
    common::RequestParameters request{
        score::cpp::span<const std::uint8_t>{message, 2U},
    };
    common::OperationIdentifier operation{};
    operation.operationActor = common::actors::OP_ACTOR_VERIFY_HANDLER;
    operation.operationAction = ::score::crypto::daemon::provider::handler::verify_handler_operations::VERIFY_SS;

    auto result = handler.Execute(operation, request);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kInsufficientParameters);
}

TEST(PqcProviderVerificationTest, ReportsPqcSizesAndResetsUsingUpstreamActions)
{
    namespace ops = provider::handler::verify_handler_operations;
    const std::pair<const char*, std::size_t> cases[] = {
        {"ML-DSA-44", 2420U}, {"ML-DSA-65", 3309U}, {"ML-DSA-87", 4627U}};
    for (const auto& test_case : cases)
    {
        PqcProviderVerifyHandler handler{std::make_unique<Executor>(),
                                         *::score::crypto::GetAlgorithmDescriptor(test_case.first)};
        EXPECT_EQ(handler.GetSignatureSize(), test_case.second);
        handler.SetOperationState(common::StreamOperationState::STREAM_ACTIVE);
        common::RequestParameters request;
        auto size = handler.Execute({common::actors::OP_ACTOR_VERIFY_HANDLER, ops::VERIFY_GET_SIZE}, request);
        ASSERT_TRUE(size.has_value());
        ASSERT_EQ(size->size(), 1U);
        EXPECT_EQ(std::get<std::uint64_t>(size->front()), test_case.second);
        EXPECT_EQ(handler.GetOperationState(), common::StreamOperationState::STREAM_ACTIVE);
        auto reset = handler.Execute({common::actors::OP_ACTOR_VERIFY_HANDLER, ops::VERIFY_RESET}, request);
        ASSERT_TRUE(reset.has_value());
        EXPECT_TRUE(reset->empty());
        EXPECT_EQ(handler.GetOperationState(), common::StreamOperationState::IDLE);
    }
    PqcProviderVerifyHandler unsupported{std::make_unique<Executor>(),
                                         *::score::crypto::GetAlgorithmDescriptor("ML-KEM-768")};
    EXPECT_EQ(unsupported.GetSignatureSize(), 0U);
}

TEST(PqcProviderVerificationTest, RejectsWrongActor)
{
    namespace ops = provider::handler::verify_handler_operations;
    PqcProviderKeyFactory factory{kProviderId};
    key_management::KeyGenerationRequest key_request{};
    key_request.algorithm = *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44");
    auto generated = factory.GenerateKey(key_request);
    ASSERT_TRUE(generated.has_value());

    PqcProviderVerifyHandler handler{std::make_unique<Executor>(),
                                     *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44")};
    provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = generated.value().get();
    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    const std::uint8_t message[] = {1U, 2U};
    const std::vector<std::uint8_t> signature(handler.GetSignatureSize());
    common::RequestParameters request{score::cpp::span<const std::uint8_t>{message, 2U},
                                      score::cpp::span<const std::uint8_t>{signature.data(), signature.size()}};
    auto wrong_actor = handler.Execute({common::actors::OP_ACTOR_SIGN_HANDLER, ops::VERIFY_SS}, request);
    ASSERT_FALSE(wrong_actor.has_value());
    EXPECT_EQ(wrong_actor.error(), common::DaemonErrorCode::kInvalidOperation);
}

TEST(PqcProviderVerificationTest, RequiresMatchingSignatureAlgorithm)
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
            PqcProviderVerifyHandler handler{std::make_unique<Executor>(), descriptor};
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

TEST(PqcProviderVerificationTest, RequiresSignatureMaterial)
{
    using key_management::KeyMaterialKind;
    PqcProviderKeyFactory factory{kProviderId};
    const auto descriptor = *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44");
    key_management::KeyGenerationRequest request{};
    request.algorithm = descriptor;
    auto generated = factory.GenerateKey(request);
    ASSERT_TRUE(generated.has_value());

    const KeyMaterialKind kinds[] = {KeyMaterialKind::kUnspecified,
                                     KeyMaterialKind::kPublicKey,
                                     KeyMaterialKind::kPrivateKey,
                                     KeyMaterialKind::kSymmetricKey,
                                     KeyMaterialKind::kSharedSecret};
    for (const auto kind : kinds)
    {
        SCOPED_TRACE(static_cast<int>(kind));
        PqcProviderVerifyHandler handler{std::make_unique<Executor>(), descriptor};
        key_management::IKeyHandler::Sptr key;
        if (kind == KeyMaterialKind::kPrivateKey)
        {
            key = generated.value();
        }
        else
        {
            std::vector<std::uint8_t> public_key;
            if (kind == KeyMaterialKind::kPublicKey)
            {
                public_key.resize(descriptor.public_key_size);
            }
            key = std::make_shared<PqcProviderKeyHandler>(
                nullptr, std::move(public_key), SignatureHandle("ML-DSA-44", kind));
        }
        provider::handler::InitializationParams params{};
        params.provider_id = kProviderId;
        params.bound_key_handler = key.get();

        const auto result = handler.InitializeContext(params);
        if (kind == KeyMaterialKind::kPublicKey || kind == KeyMaterialKind::kPrivateKey)
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

TEST(PqcProviderVerificationTest, ClearsKeyAfterFailedRebind)
{
    PqcProviderKeyFactory factory{kProviderId};
    const auto descriptor = *::score::crypto::GetAlgorithmDescriptor("ML-DSA-44");
    key_management::KeyGenerationRequest request{};
    request.algorithm = descriptor;
    auto generated = factory.GenerateKey(request);
    ASSERT_TRUE(generated.has_value());

    PqcProviderVerifyHandler handler{std::make_unique<Executor>(), descriptor};
    provider::handler::InitializationParams params{};
    params.provider_id = kProviderId;
    params.bound_key_handler = generated.value().get();
    ASSERT_TRUE(handler.InitializeContext(params).has_value());

    PqcProviderKeyHandler incompatible_key{nullptr, {}, SignatureHandle("ML-DSA-65")};
    params.bound_key_handler = &incompatible_key;
    const auto result = handler.InitializeContext(params);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);

    const auto verify = handler.SingleShotVerify({}, {});
    ASSERT_FALSE(verify.has_value());
    EXPECT_EQ(verify.error(), common::DaemonErrorCode::kKeySlotEmpty);
}
}  // namespace
