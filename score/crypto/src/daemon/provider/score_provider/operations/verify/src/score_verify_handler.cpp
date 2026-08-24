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

#include "score/crypto/src/daemon/provider/score_provider/operations/verify/score_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::verify
{
ScoreVerifyHandler::ScoreVerifyHandler(std::unique_ptr<VerifyExecutor> executor, const common::AlgorithmId algorithm)
    : m_algorithm{std::move(algorithm)}, m_executor{std::move(executor)}
{
}
ScoreVerifyHandler::~ScoreVerifyHandler() = default;

Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreVerifyHandler::Execute(
    const common::OperationIdentifier& id, common::RequestParameters& request)
{
    return m_executor->Execute(*this, id, request);
}
Expected<std::monostate, common::DaemonErrorCode> ScoreVerifyHandler::InitializeContext(
    const handler::InitializationParams&)
{
    m_state = common::StreamOperationState::IDLE;
    return std::monostate{};
}
Expected<std::monostate, common::DaemonErrorCode> ScoreVerifyHandler::Reset()
{
    m_state = common::StreamOperationState::IDLE;
    return std::monostate{};
}
Expected<std::monostate, common::DaemonErrorCode> ScoreVerifyHandler::InitVerify(
    std::optional<common::RequestParameter>)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
Expected<std::monostate, common::DaemonErrorCode> ScoreVerifyHandler::UpdateVerify(
    const common::RequestParameter&)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
Expected<bool, common::DaemonErrorCode> ScoreVerifyHandler::FinalizeVerify(
    std::optional<common::RequestParameter>, std::optional<common::RequestParameter>)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
Expected<bool, common::DaemonErrorCode> ScoreVerifyHandler::SingleShotVerify(
    const common::RequestParameter&, const common::RequestParameter&)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
}  // namespace score::crypto::daemon::provider::score_provider::operations::verify
