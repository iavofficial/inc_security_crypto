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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_IAV_PRIMULA_OPERATIONS_KEM_IAV_PRIMULA_KEM_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_IAV_PRIMULA_OPERATIONS_KEM_IAV_PRIMULA_KEM_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/operations/kem/score_kem_handler.hpp"
#include "score/iav_primula/include/iav_primula_ffi.h"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{

/// @brief iavPrimula implementation of the provider-neutral KEM handler.
class IavPrimulaKemHandler final : public operations::kem::ScoreKemHandler
{
  public:
    IavPrimulaKemHandler(std::unique_ptr<operations::kem::KemExecutor> executor,
                         common::AlgorithmId algorithm);
    ~IavPrimulaKemHandler() override = default;

    IavPrimulaKemHandler(const IavPrimulaKemHandler&) = delete;
    IavPrimulaKemHandler& operator=(const IavPrimulaKemHandler&) = delete;

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams& init_params) override;
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> GenerateKeyPair() override;
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Encapsulate(
        const common::RequestParameter& request) override;
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Decapsulate(
        const common::RequestParameter& request) override;

  private:
    [[nodiscard]] Expected<iav_algorithm, common::DaemonErrorCode> GetAlgorithm() const noexcept;
    iav_primula_key_handle* m_key{nullptr};
};

}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

#endif
