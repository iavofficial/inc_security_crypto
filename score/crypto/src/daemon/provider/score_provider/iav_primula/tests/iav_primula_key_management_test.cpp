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

// ---------------------------------------------------------------------------
// Import validation
// ---------------------------------------------------------------------------

TEST(IavPrimulaKeyManagementTest, RejectsInvalidAlgorithmsAndKeys)
{
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    key_management::KeyImportRequest request{};

    // KEM public-key import validates the same public-key size as ML-DSA.
    request.algorithm = "ML-KEM-768";
    std::vector<std::uint8_t> kem_key(1184U);
    request.key_data = kem_key.data();
    request.key_data_size = kem_key.size() - 1U;
    auto unsupported_result = factory.ImportKey(request);
    ASSERT_FALSE(unsupported_result.has_value());
    EXPECT_EQ(unsupported_result.error(), common::DaemonErrorCode::kInvalidArgument);

    // ML-DSA-44 public keys contain 1312 bytes; import one byte less
    // deliberately to verify key-size validation.
    request.algorithm = "ML-DSA-44";
    std::vector<std::uint8_t> key(1312U);
    request.key_data = key.data();
    request.key_data_size = key.size() - 1U;
    auto invalid_result = factory.ImportKey(request);
    ASSERT_FALSE(invalid_result.has_value());
    EXPECT_EQ(invalid_result.error(), common::DaemonErrorCode::kInvalidArgument);
}

// ---------------------------------------------------------------------------
// Public-key ownership and lifecycle
// ---------------------------------------------------------------------------

TEST(IavPrimulaKeyManagementTest, CopiesExportsAndReleasesPublicKey)
{
    key_management::ProviderKeyHandle handle{};
    handle.permissions = score::crypto::KeyOperationPermission::kExport;
    // Use synthetic public-key material to verify that the handler copies it.
    std::vector<std::uint8_t> public_key(8U, 0xA5U);
    IavPrimulaKeyHandler key{nullptr, public_key, handle};
    public_key[0] = 0U;

    // Export must return the copied key data, not the modified source vector.
    auto exported = key.Export();
    ASSERT_TRUE(exported.has_value());
    EXPECT_EQ(exported->bytes, std::vector<std::uint8_t>(8U, 0xA5U));

    // Releasing the key prevents subsequent export operations.
    EXPECT_TRUE(key.Release().has_value());
    auto released_export = key.Export();
    ASSERT_FALSE(released_export.has_value());
    EXPECT_EQ(released_export.error(), common::DaemonErrorCode::kKeyOperationNotPermitted);
}

TEST(IavPrimulaKeyManagementTest, PreservesImportedPublicKeyPermissions)
{
    using Permission = score::crypto::KeyOperationPermission;
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    const std::vector<std::uint8_t> public_key(1312U, 0xA5U);
    key_management::KeyImportRequest request{};
    request.algorithm = "ML-DSA-44";
    request.key_data = public_key.data();
    request.key_data_size = public_key.size();
    request.permissions = Permission::kExport;
    auto imported = factory.ImportKey(request);
    ASSERT_TRUE(imported.has_value());
    const auto& handle = imported.value()->GetHandle();
    EXPECT_EQ(handle.permissions, Permission::kNone);
    ASSERT_TRUE(handle.public_key_permissions.has_value());
    EXPECT_EQ(handle.public_key_permissions.value(), Permission::kExport);
    EXPECT_FALSE(score::crypto::HasPermission(
        key_management::GrantedPermissionsFor(handle, Permission::kVerify), Permission::kVerify));
    auto exported = imported.value()->Export();
    ASSERT_TRUE(exported.has_value());
    EXPECT_EQ(exported->bytes, public_key);

    request.permissions = Permission::kVerify;
    auto verify_only = factory.ImportKey(request);
    ASSERT_TRUE(verify_only.has_value());
    EXPECT_TRUE(score::crypto::HasPermission(
        key_management::GrantedPermissionsFor(verify_only.value()->GetHandle(), Permission::kVerify),
        Permission::kVerify));
    auto denied = verify_only.value()->Export();
    ASSERT_FALSE(denied.has_value());
    EXPECT_EQ(denied.error(), common::DaemonErrorCode::kKeyOperationNotPermitted);
}

// ---------------------------------------------------------------------------
// Key-generation dispatch
// ---------------------------------------------------------------------------

TEST(IavPrimulaKeyManagementTest, RoutesKemKeyGenerationToKemBackendPath)
{
    IavPrimulaKeyFactory factory{common::ProviderId{7U}};
    key_management::KeyGenerationRequest request{};
    request.algorithm = "ML-KEM-768";

    // The current Rust FFI is a deliberate placeholder and therefore returns
    // an operation failure. The call still exercises the KEM-specific branch
    // in the factory; once the FFI is implemented this test should be changed
    // to assert the generated key metadata and public-key size.
    auto result = factory.GenerateKey(request);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), common::DaemonErrorCode::kOperationFailed);
}
}  // namespace
