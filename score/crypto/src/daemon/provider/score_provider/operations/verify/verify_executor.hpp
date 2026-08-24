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

/// @file verify_executor.hpp
/// @brief Operation dispatcher for provider-neutral verification handlers.

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_VERIFY_EXECUTOR_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPERATIONS_VERIFY_VERIFY_EXECUTOR_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::verify
{
class ScoreVerifyHandler;

/// @brief Stateless executor implementing orchestration and visitor pattern for verification
///        operations under the score interface family.
///
/// Responsibilities:
///   - Orchestrates operation flow and validates state transitions
///   - Routes operations to ScoreVerifyHandler typed methods via visitor pattern
///   - Decouples operation invocation from handler implementation
class VerifyExecutor final
{
  public:
    /// @brief Execute one VERIFY operation.
    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        ScoreVerifyHandler&, const common::OperationIdentifier&, common::RequestParameters&);

  private:
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteInit(ScoreVerifyHandler& handler,
                                                                                common::RequestParameters& request);

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteUpdate(ScoreVerifyHandler& handler,
                                                                                  common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteFinalize(
        ScoreVerifyHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] Expected<common::ResponseParameters, common::DaemonErrorCode> ExecuteSingleShot(
        ScoreVerifyHandler& handler,
        common::RequestParameters& request);

    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> ExecuteReset(ScoreVerifyHandler& handler,
                                                                                 common::RequestParameters& request);

    [[nodiscard]] static Expected<std::monostate, common::DaemonErrorCode> ValidateStreamTransition(
        common::OperationAction action,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState);

};
}  // namespace score::crypto::daemon::provider::score_provider::operations::verify

#endif
