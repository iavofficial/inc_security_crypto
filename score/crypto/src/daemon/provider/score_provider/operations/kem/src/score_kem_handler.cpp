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

#include "score/crypto/src/daemon/provider/score_provider/operations/kem/score_kem_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/kem/kem_executor.hpp"
namespace score::crypto::daemon::provider::score_provider::operations::kem
{
ScoreKemHandler::ScoreKemHandler(std::unique_ptr<KemExecutor> e, common::AlgorithmId a)
    : m_algorithm{std::move(a)}, m_executor{std::move(e)}
{
}
ScoreKemHandler::~ScoreKemHandler() = default;
Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreKemHandler::Execute(
    const common::OperationIdentifier& id, common::RequestParameters& r)
{
    return m_executor->Execute(*this, id, r);
}
Expected<std::monostate, common::DaemonErrorCode> ScoreKemHandler::InitializeContext(
    const handler::InitializationParams&)
{
    return {};
}
Expected<std::monostate, common::DaemonErrorCode> ScoreKemHandler::Reset()
{
    return {};
}
Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreKemHandler::GenerateKeyPair()
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreKemHandler::Encapsulate(
    const common::RequestParameter&)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
Expected<common::ResponseParameters, common::DaemonErrorCode> ScoreKemHandler::Decapsulate(
    const common::RequestParameter&)
{
    return make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
}
}  // namespace score::crypto::daemon::provider::score_provider::operations::kem
