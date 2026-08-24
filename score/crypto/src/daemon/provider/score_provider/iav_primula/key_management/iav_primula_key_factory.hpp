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
#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEY_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEY_FACTORY_HPP

#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{
class IavPrimulaKeyFactory final : public key_management::IKeyFactory
{
  public:
    explicit IavPrimulaKeyFactory(common::ProviderId id) : m_provider_id{id} {}
    [[nodiscard]] Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode> GenerateKey(
        const key_management::KeyGenerationRequest&) override;
    [[nodiscard]] Expected<key_management::IKeyHandler::Sptr, common::DaemonErrorCode> ImportKey(
        const key_management::KeyImportRequest&) override;

  private:
    common::ProviderId m_provider_id;
};
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula
#endif
