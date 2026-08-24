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

#include "score/crypto/src/daemon/provider/score_provider/operations/sign/score_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::sign
{
ScoreSignHandler::ScoreSignHandler(std::unique_ptr<SignExecutor> executor, const common::AlgorithmId algorithm)
    : m_algorithm{std::move(algorithm)}, m_executor{std::move(executor)}
{
}
ScoreSignHandler::~ScoreSignHandler() = default;

Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreSignHandler::Execute(
    const common::OperationIdentifier& id, common::RequestParameters& request)
{
    return m_executor->Execute(*this, id, request);
}
Expected<std::monostate, common::DaemonErrorCode> ScoreSignHandler::InitializeContext(
    const handler::InitializationParams&)
{
    m_state = common::StreamOperationState::IDLE;
    return std::monostate{};
}
Expected<std::monostate, common::DaemonErrorCode> ScoreSignHandler::Reset()
{
    m_state = common::StreamOperationState::IDLE;
    return std::monostate{};
}
Expected<std::monostate, common::DaemonErrorCode> ScoreSignHandler::InitSign(std::optional<common::RequestParameter>)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
Expected<std::monostate, common::DaemonErrorCode> ScoreSignHandler::UpdateSign(const common::RequestParameter&)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreSignHandler::FinalizeSign(
    std::optional<common::RequestParameter>, std::optional<common::RequestParameter>)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreSignHandler::SingleShotSign(
    const common::RequestParameter&, std::optional<common::RequestParameter>)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreSignHandler::GetSignatureSize() const
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
}  // namespace score::crypto::daemon::provider::score_provider::operations::sign
