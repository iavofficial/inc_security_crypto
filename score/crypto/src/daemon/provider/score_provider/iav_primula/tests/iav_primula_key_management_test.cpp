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

#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_factory.hpp"
#include "score/crypto/src/daemon/provider/score_provider/iav_primula/key_management/iav_primula_key_handler.hpp"

#include <gtest/gtest.h>

namespace
{
using namespace score::crypto::daemon;
using namespace score::crypto::daemon::provider::score_provider::iav_primula;

TEST(IavPrimulaKeyManagementTest, RejectsInvalidAlgorithmsAndKeys)
{
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    key_management::KeyImportRequest request{};
    request.algorithm = "ML-KEM-768";
    auto kem_result = factory.ImportKey(request);
    ASSERT_FALSE(kem_result.has_value());
    EXPECT_EQ(kem_result.error(), common::DaemonErrorCode::kInvalidArgument);

    request.algorithm = "ML-DSA-44";
    std::vector<std::uint8_t> key(1312U);
    request.key_data = key.data();
    request.key_data_size = key.size() - 1U;
    auto invalid_result = factory.ImportKey(request);
    ASSERT_FALSE(invalid_result.has_value());
    EXPECT_EQ(invalid_result.error(), common::DaemonErrorCode::kInvalidArgument);
}

TEST(IavPrimulaKeyManagementTest, CopiesExportsAndReleasesPublicKey)
{
    key_management::ProviderKeyHandle handle{};
    handle.permissions = score::crypto::KeyOperationPermission::kExport;
    std::vector<std::uint8_t> public_key(8U, 0xA5U);
    IavPrimulaKeyHandler key{nullptr, public_key, handle};
    public_key[0] = 0U;

    auto exported = key.Export();
    ASSERT_TRUE(exported.has_value());
    EXPECT_EQ(exported->bytes, std::vector<std::uint8_t>(8U, 0xA5U));
    EXPECT_TRUE(key.Release().has_value());
    auto released_export = key.Export();
    ASSERT_FALSE(released_export.has_value());
    EXPECT_EQ(released_export.error(), common::DaemonErrorCode::kKeyOperationNotPermitted);
}
}  // namespace
