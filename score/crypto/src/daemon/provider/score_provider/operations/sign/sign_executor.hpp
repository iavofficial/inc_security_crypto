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

/// @file sign_executor.hpp
/// @brief Operation dispatcher for provider-neutral signature handlers.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SIGN_EXECUTOR_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_SIGN_SIGN_EXECUTOR_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::sign
{
class ScoreSignHandler;

/// @brief Stateless executor implementing orchestration and visitor pattern for sign
///        operations under the score interface family.
///
/// Responsibilities:
///   - Orchestrates operation flow and validates state transitions
///   - Routes operations to ScoreSignHandler typed methods via visitor pattern
///   - Decouples operation invocation from handler implementation
class SignExecutor final
{
  public:
    /// @brief Execute one SIGN operation.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        ScoreSignHandler&, const common::OperationIdentifier&, common::RequestParameters&);
  private:
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteInit(ScoreSignHandler& handler,
                                                                                common::RequestParameters& request);

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteUpdate(ScoreSignHandler& handler,
                                                                                  common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteFinalize(
        ScoreSignHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSingleShot(
        ScoreSignHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteReset(ScoreSignHandler& handler,
                                                                                 common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> GetSignatureSize(
        const ScoreSignHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] static Expected<std::monostate, common::DaemonErrorCode> ValidateStreamTransition(
        common::OperationAction action,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState);

};
}  // namespace score::crypto::daemon::provider::score_provider::operations::sign

#endif
