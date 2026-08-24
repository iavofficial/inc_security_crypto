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

#include "primula_backend_adapter.hpp"

#include "score/crypto/src/daemon/provider/score_provider/iav_primula/iav_primula_provider.hpp"

namespace score::crypto::backend::score_provider::primula
{

daemon::provider::score_provider::ProviderCreator PrimulaBackendAdapter::GetProviderCreator() const
{
    using namespace daemon::provider::score_provider;

    return ProviderCreator{.backend_id = "primula",
                           .backend_name = "PRIMULA",
                           .provider_type = "SOFTWARE",
                           .create_provider = []() -> std::unique_ptr<daemon::provider::IProvider> {
                               return std::make_unique<daemon::provider::score_provider::iav_primula::IavPrimulaProvider>();
                           }};
}

}  // namespace score::crypto::backend::score_provider::primula
