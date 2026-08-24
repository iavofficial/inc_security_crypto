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
#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_SCORE_VERIFY_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_SCORE_VERIFY_HANDLER_HPP

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"
#include <memory>
#include <optional>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::operations::verify
{
class VerifyExecutor;

/// @brief Abstract base handler for verification operations under the score interface family.
///
/// Implements the daemon's Handler interface by delegating Execute() to the
/// injected VerifyExecutor. Concrete score-interface providers (e.g. OpenSSL, IAV_Primula)
/// inherit from this class and override the typed verification methods.
///
/// Typed methods default to kUnsupportedOperation so that a partially-implemented
/// provider compiles and returns a clear error at runtime.
///
/// State management (algorithm, stream operation state) is centralised here.
class ScoreVerifyHandler : public handler::Handler
{
  public:
    using Sptr = std::shared_ptr<ScoreVerifyHandler>;

    ScoreVerifyHandler() = delete;

    ScoreVerifyHandler(std::unique_ptr<VerifyExecutor> executor, const common::AlgorithmId algorithm);
    ~ScoreVerifyHandler() override;

    /// @brief Delegates to the injected executor.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier&, common::RequestParameters&) override;

    /// @brief Validates algorithm and resets state to IDLE.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const handler::InitializationParams&) override;

    /// @brief Resets intermediate state back to IDLE.
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Reset() override;

    // -----------------------------------------------------------------------
    // Stream state management
    // -----------------------------------------------------------------------

    [[nodiscard]] common::StreamOperationState GetOperationState() const noexcept
    {
        return m_state;
    }

    void SetOperationState(common::StreamOperationState s) noexcept
    {
        m_state = s;
    }

    [[nodiscard]] const common::AlgorithmId& GetAlgorithm() const noexcept
    {
        return m_algorithm;
    }

    // -----------------------------------------------------------------------
    // Typed verification operations — override in concrete provider handlers
    // -----------------------------------------------------------------------

    /// @brief Initialize a verification operation on an existing context.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> InitVerify(
        std::optional<common::RequestParameter>);

    /// @brief Add data to the active verification stream.
    [[nodiscard]] virtual Expected<std::monostate, common::DaemonErrorCode> UpdateVerify(
        const common::RequestParameter&);

    /// @brief Finalize the verification and produce the output.
    [[nodiscard]] virtual Expected<bool, common::DaemonErrorCode> FinalizeVerify(
        std::optional<common::RequestParameter>, std::optional<common::RequestParameter>);

    /// @brief Perform single-shot verification without streaming.
    [[nodiscard]] virtual Expected<bool, common::DaemonErrorCode> SingleShotVerify(
        const common::RequestParameter&, const common::RequestParameter&);

  protected:
    common::AlgorithmId m_algorithm;
    common::StreamOperationState m_state{common::StreamOperationState::IDLE};

  private:
    std::unique_ptr<VerifyExecutor> m_executor;
};
}  // namespace score::crypto::daemon::provider::score_provider::operations::verify

#endif
