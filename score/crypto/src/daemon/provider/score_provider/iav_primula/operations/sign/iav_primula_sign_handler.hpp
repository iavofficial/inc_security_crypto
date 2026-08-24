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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_IAV_PRIMULA_OPERATIONS_HASH_IAV_PRIMULA_SIGN_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_IAV_PRIMULA_OPERATIONS_HASH_IAV_PRIMULA_SIGN_HANDLER_HPP

#include "score/iav_primula/include/iav_primula_ffi.h"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/score_sign_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

/// @brief iavPrimula implementation of the generic signature handler.
class IavPrimulaSignHandler final : public operations::sign::ScoreSignHandler
{
  public:
    IavPrimulaSignHandler(
        std::unique_ptr<operations::sign::SignExecutor> executor,
        common::AlgorithmId algorithm);

    ~IavPrimulaSignHandler() override = default;

    IavPrimulaSignHandler(const IavPrimulaSignHandler&) = delete;
    IavPrimulaSignHandler& operator=(const IavPrimulaSignHandler&) = delete;
    IavPrimulaSignHandler(IavPrimulaSignHandler&&) = delete;
    IavPrimulaSignHandler& operator=(IavPrimulaSignHandler&&) = delete;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams& init_params) override;
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Reset() override;
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> SingleShotSign(
        const common::RequestParameter& data,
        std::optional<common::RequestParameter> output) override;
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> GetSignatureSize() const override;

  private:
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ValidateAlgorithm() const;
    [[nodiscard]] std::size_t GetExpectedSignatureSize() const noexcept;

    iav_primula_key_handle* m_key{nullptr};
    std::vector<std::uint8_t> m_outputBuffer;
};

}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

#endif
