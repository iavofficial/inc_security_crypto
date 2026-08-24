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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_VERIFY_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_VERIFY_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/operations/verify/score_verify_handler.hpp"
#include "score/iav_primula/include/iav_primula_ffi.h"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{
class IavPrimulaVerifyHandler final : public operations::verify::ScoreVerifyHandler
{
  public:
    IavPrimulaVerifyHandler(std::unique_ptr<operations::verify::VerifyExecutor> executor,
                            common::AlgorithmId algorithm);
    ~IavPrimulaVerifyHandler() override = default;

    IavPrimulaVerifyHandler(const IavPrimulaVerifyHandler&) = delete;
    IavPrimulaVerifyHandler& operator=(const IavPrimulaVerifyHandler&) = delete;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;
    [[nodiscard]] Expected<bool, common::DaemonErrorCode> SingleShotVerify(
        const common::RequestParameter& data, const common::RequestParameter& signature) override;

  private:
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ValidateAlgorithm() const;
    iav_primula_key_handle* m_key{nullptr};
};
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

#endif
