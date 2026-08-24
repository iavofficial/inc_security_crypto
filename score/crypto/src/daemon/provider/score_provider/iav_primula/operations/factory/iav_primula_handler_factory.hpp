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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_IAV_PRIMULA_HANDLER_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_IAV_PRIMULA_HANDLER_FACTORY_HPP

#include "score/crypto/src/daemon/provider/score_provider/operations/factory/score_handler_factory.hpp"
#include "score/result/result.h"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

/// @brief Factory for iavPrimula SIGN, VERIFY, and KEM handlers.
class IavPrimulaHandlerFactory final : public ::score::crypto::daemon::provider::score_provider::operations::factory::ScoreHandlerFactory
{
  public:
    IavPrimulaHandlerFactory(std::shared_ptr<key_management::IKeyFactory> key_factory,
                             std::shared_ptr<key_management::IKeySlotHandler> slot_handler,
                             key_management::KeyManagementService::Sptr km_service);

    ~IavPrimulaHandlerFactory() override = default;

    IavPrimulaHandlerFactory(const IavPrimulaHandlerFactory&) = delete;
    IavPrimulaHandlerFactory& operator=(const IavPrimulaHandlerFactory&) = delete;
    IavPrimulaHandlerFactory(IavPrimulaHandlerFactory&&) = delete;
    IavPrimulaHandlerFactory& operator=(IavPrimulaHandlerFactory&&) = delete;

  protected:
    [[nodiscard]] ::score::Result<::score::crypto::daemon::provider::handler::Handler::Sptr> CreateSignHandler(
        const common::AlgorithmId& algorithm) override;

    [[nodiscard]] ::score::Result<::score::crypto::daemon::provider::handler::Handler::Sptr> CreateVerifyHandler(
        const common::AlgorithmId& algorithm) override;

    [[nodiscard]] ::score::Result<::score::crypto::daemon::provider::handler::Handler::Sptr> CreateKemHandler(
        const common::AlgorithmId& algorithm) override;
};

}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_IAV_PRIMULA_HANDLER_FACTORY_HPP
