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

#ifndef SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_CORE_KEY_MANAGEMENT_AUTHORIZATION_HPP
#define SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_CORE_KEY_MANAGEMENT_AUTHORIZATION_HPP

#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"

namespace score::crypto::daemon::key_management
{

/// @brief Select the permission set applicable to an operation; this does not authorize it.
///
/// Public-key resources use public_key_permissions for every operation.
/// For other asymmetric resources, verify, encrypt and wrap use the public
/// half's permissions; other operations use permissions. Symmetric keys and
/// shared secrets use permissions. Unset public-key permissions are unrestricted.
[[nodiscard]] inline score::crypto::KeyOperationPermission PermissionSetForOperation(
    const ProviderKeyHandle& handle,
    score::crypto::KeyOperationPermission required) noexcept
{
    using Permission = score::crypto::KeyOperationPermission;

    if (handle.material_kind == KeyMaterialKind::kPublicKey)
    {
        return handle.public_key_permissions.value_or(Permission::kAll);
    }

    constexpr Permission kPublicHalfOperations = Permission::kVerify | Permission::kEncrypt | Permission::kWrap;
    if (handle.is_asymmetric && score::crypto::HasPermission(kPublicHalfOperations, required))
    {
        return handle.public_key_permissions.value_or(Permission::kAll);
    }
    return handle.permissions;
}

/// @brief Select permissions for the material represented by a key export.
/// Raw EC export contains only the public point and uses public-key permissions.
/// Other encodings use the permission set for a normal key export.
[[nodiscard]] inline score::crypto::KeyOperationPermission PermissionSetForExport(
    const ProviderKeyHandle& handle,
    score::crypto::FormatType format) noexcept
{
    if (handle.is_asymmetric && format == score::crypto::FormatType::kRaw &&
        handle.algorithm.key_type == score::crypto::KeyType::kEcc)
    {
        return handle.public_key_permissions.value_or(score::crypto::KeyOperationPermission::kAll);
    }
    return PermissionSetForOperation(handle, score::crypto::KeyOperationPermission::kExport);
}

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_KEY_MANAGEMENT_CORE_KEY_MANAGEMENT_AUTHORIZATION_HPP
