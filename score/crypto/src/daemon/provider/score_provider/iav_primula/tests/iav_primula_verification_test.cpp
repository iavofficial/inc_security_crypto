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

#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/operations/verify/iav_primula_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"

#include <gtest/gtest.h>

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider::score_provider::iav_primula;
using Executor = score::crypto::daemon::provider::score_provider::operations::verify::VerifyExecutor;

TEST(IavPrimulaVerificationTest, RejectsUnsupportedAndMissingKeys)
{
    IavPrimulaVerifyHandler kem{std::make_unique<Executor>(), "ML-KEM-768"};
    auto kem_result = kem.InitializeContext({});
    ASSERT_FALSE(kem_result.has_value());
    EXPECT_EQ(kem_result.error(), common::DaemonErrorCode::kUnsupportedAlgorithm);

    IavPrimulaVerifyHandler handler{std::make_unique<Executor>(), "ML-DSA-44"};
    auto result = handler.InitializeContext({});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kKeySlotEmpty);
}

TEST(IavPrimulaVerificationTest, ValidatesKeyTypeAndSignatureSize)
{
    IavPrimulaVerifyHandler handler{std::make_unique<Executor>(), "ML-DSA-44"};
    IavPrimulaKeyHandler public_key{nullptr, std::vector<std::uint8_t>(1312U), {}};
    ::score::crypto::daemon::provider::handler::InitializationParams params{};
    params.bound_key_handler = &public_key;
    auto result = handler.InitializeContext(params);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kIncompatibleKeyType);

    IavPrimulaKeyHandler key{reinterpret_cast<iav_primula_key_handle*>(0x1), {}, {}};
    params.bound_key_handler = &key;
    ASSERT_TRUE(handler.InitializeContext(params).has_value());
    const std::uint8_t message[] = {1U, 2U};
    std::vector<std::uint8_t> signature(10U);
    common::RequestParameter input = common::VirtualMemoryBufferConst{message, 2U};
    auto verify = handler.SingleShotVerify(
        input, common::VirtualMemoryBufferConst{signature.data(), signature.size()});
    EXPECT_EQ(verify.error(), common::DaemonErrorCode::kInvalidArgument);
}
}  // namespace
