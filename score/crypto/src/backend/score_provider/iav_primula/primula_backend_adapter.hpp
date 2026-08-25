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

#ifndef SCORE_CRYPTO_SRC_BACKEND_SCORE_PROVIDER_PRIMULA_PRIMULA_BACKEND_ADAPTER_HPP
#define SCORE_CRYPTO_SRC_BACKEND_SCORE_PROVIDER_PRIMULA_PRIMULA_BACKEND_ADAPTER_HPP

#include "score/crypto/src/daemon/provider/score_provider/score_backend_adapter.hpp"

namespace score::crypto::backend::score_provider::primula
{

/// @brief OpenSSL backend adapter for score provider family
///
/// Provides factory creation metadata for the OpenSSL crypto backend.
/// This adapter is discovered at compile-time via
/// backend/score_provider/active_backends_list.hpp.
///
/// The OpenSSL backend implementation lives in:
///   - daemon/provider/score_provider/iav_primula/provider_primula.*
///   - daemon/provider/score_provider/iav_primula/operations/*
///
/// This adapter serves as the registration/enablement layer only.
class PrimulaBackendAdapter final : public daemon::provider::score_provider::IBackendProviderAdapter
{
  public:
    PrimulaBackendAdapter() = default;
    ~PrimulaBackendAdapter() override = default;

    PrimulaBackendAdapter(const PrimulaBackendAdapter&) = delete;
    PrimulaBackendAdapter& operator=(const PrimulaBackendAdapter&) = delete;
    PrimulaBackendAdapter(PrimulaBackendAdapter&&) = delete;
    PrimulaBackendAdapter& operator=(PrimulaBackendAdapter&&) = delete;

    /// @brief Get provider creator for the OpenSSL backend.
    ///
    /// Returns:
    ///   - backend_id:    "primula"
    ///   - backend_name:  "PRIMULA"
    ///   - provider_type: "SPECIALIZED"
    ///   - create_provider: constructs and returns a unique_ptr<OpenSSL>
    [[nodiscard]] daemon::provider::score_provider::ProviderCreator GetProviderCreator() const override;
};

}  // namespace score::crypto::backend::score_provider::primula

#endif  // SCORE_CRYPTO_SRC_BACKEND_SCORE_PROVIDER_PRIMULA_PRIMULA_BACKEND_ADAPTER_HPP
