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

/// @file score_kem_handler.hpp
/// @brief Provider-neutral base handler for KEM operations.

#ifndef SCORE_CRYPTO_DAEMON_SCORE_PROVIDER_KEM_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_SCORE_PROVIDER_KEM_HANDLER_HPP

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"
#include <memory>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::operations::kem
{
class KemExecutor;
class ScoreKemHandler : public handler::Handler
{
  public:
    ScoreKemHandler(std::unique_ptr<KemExecutor>, common::AlgorithmId);
    ~ScoreKemHandler() override;
    Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier&, common::RequestParameters&) override;
    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams&) override;
    Expected<std::monostate, common::DaemonErrorCode> Reset() override;
    virtual Expected<common::ResponseParameters, common::DaemonErrorCode> GenerateKeyPair();
    virtual Expected<common::ResponseParameters, common::DaemonErrorCode> Encapsulate(
        const common::RequestParameter&);
    virtual Expected<common::ResponseParameters, common::DaemonErrorCode> Decapsulate(
        const common::RequestParameter&);
  protected:
    common::AlgorithmId m_algorithm;

  private:
    std::unique_ptr<KemExecutor> m_executor;
};
}  // namespace score::crypto::daemon::provider::score_provider::operations::kem

#endif
