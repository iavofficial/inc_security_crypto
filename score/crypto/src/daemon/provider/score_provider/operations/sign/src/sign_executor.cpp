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

#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/sign_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/score_sign_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::operations::sign
{
namespace handler = ::score::crypto::daemon::provider::handler;
using common::DaemonErrorCode;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;

Expected<ResponseParameters, DaemonErrorCode> SignExecutor::Execute(ScoreSignHandler& handler,
                                                                                    const common::OperationIdentifier& operationId,
                                                                                    RequestParameters& request)
{
    if (operationId.operationAction == handler::sign_handler_operations::SIGN_GET_SIGNATURE_SIZE)
    {
        return  GetSignatureSize(handler, request);
    }

    if (operationId.operationAction == handler::sign_handler_operations::SIGN_RESET)
    {
        auto result = ExecuteReset(handler, request);
        if (!result.has_value())
        {
            return make_unexpected(result.error());
        }
        return ResponseParameters{};
    }

    if (operationId.operationAction == handler::sign_handler_operations::SIGN_SS)
    {
        StreamOperationState state = handler.GetOperationState();
        if (state != StreamOperationState::IDLE)
        {
            return make_unexpected(DaemonErrorCode::kOperationInProgress);
        }
        if (request.empty())
        {
            return make_unexpected(DaemonErrorCode::kInsufficientParameters);
        }

        return ExecuteSingleShot(handler, request);
    }

    // Streaming operations: validate state machine transition
    StreamOperationState currentState = handler.GetOperationState();
    StreamOperationState nextState = StreamOperationState::IDLE;
    const auto sequenceValidation = ValidateStreamTransition(operationId.operationAction, currentState, nextState);
    if (!sequenceValidation.has_value())
    {
        return make_unexpected(sequenceValidation.error());
    }

    if (operationId.operationAction == handler::sign_handler_operations::SIGN_FINALIZE)
    {
        auto result = ExecuteFinalize(handler, request);
        if (result.has_value())
        {
            handler.SetOperationState(nextState);
        }
        return result;
    }

    const auto result = [&]() -> Expected<std::monostate, DaemonErrorCode> {
        if (operationId.operationAction == handler::sign_handler_operations::SIGN_INIT)
        {
            return ExecuteInit(handler, request);
        }
        if (operationId.operationAction == handler::sign_handler_operations::SIGN_UPDATE)
        {
            return ExecuteUpdate(handler, request);
        }
        return make_unexpected(DaemonErrorCode::kInvalidOperation);
    }();

    if (result.has_value())
    {
        handler.SetOperationState(nextState);
    }
    else
    {
        return make_unexpected(result.error());
    }

    return ResponseParameters{};
}

Expected<std::monostate, DaemonErrorCode> SignExecutor::ExecuteInit(ScoreSignHandler& handler,
                                                                    RequestParameters& request)
{
    std::optional<score::cpp::span<const std::uint8_t>> initialData;
    if (!request.empty())
    {
        if (auto* buf = std::get_if<score::cpp::span<const std::uint8_t>>(&request[0]))
        {
            initialData.emplace(*buf);
        }
    }
    return handler.InitSign(initialData);
}

Expected<std::monostate, DaemonErrorCode> SignExecutor::ExecuteUpdate(ScoreSignHandler& handler,
                                                                      RequestParameters& request)
{
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    auto* buf = std::get_if<score::cpp::span<const std::uint8_t>>(&request[0]);
    if (buf == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kInvalidDataType);
    }

    return handler.UpdateSign(*buf);
}

Expected<ResponseParameters, DaemonErrorCode> SignExecutor::ExecuteFinalize(ScoreSignHandler& handler,
                                                                            RequestParameters& request)
{
    std::optional<score::cpp::span<std::uint8_t>> output;
    if (!request.empty())
    {
        if (auto* buf = std::get_if<score::cpp::span<std::uint8_t>>(&request[0]))
        {
            output.emplace(*buf);
        }
    }

    std::optional<score::cpp::span<const std::uint8_t>> finalData;
    if (request.size() > 1)
    {
        if (auto* buf = std::get_if<score::cpp::span<const std::uint8_t>>(&request[1]))
        {
            finalData.emplace(*buf);
        }
    }

    return handler.FinalizeSign(output, finalData);
}

Expected<ResponseParameters, DaemonErrorCode> SignExecutor::ExecuteSingleShot(ScoreSignHandler& handler,
                                                                              RequestParameters& request)
{
    if (request.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    auto* data = std::get_if<score::cpp::span<const std::uint8_t>>(&request[0]);
    if (data == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kInvalidDataType);
    }

    std::optional<score::cpp::span<std::uint8_t>> output;
    if (request.size() > 1)
    {
        if (auto* buf = std::get_if<score::cpp::span<std::uint8_t>>(&request[1]))
        {
            output.emplace(*buf);
        }
    }

    return handler.SingleShotSign(*data, output);
}

Expected<std::monostate, DaemonErrorCode> SignExecutor::ExecuteReset(ScoreSignHandler& handler,
                                                                     RequestParameters& /*request*/)
{
    return handler.Reset();
}

Expected<ResponseParameters, DaemonErrorCode> SignExecutor::GetSignatureSize(const ScoreSignHandler& handler,
                                                                             RequestParameters& /*request*/)
{
    return handler.GetSignatureSize();
}

// static
Expected<std::monostate, DaemonErrorCode> SignExecutor::ValidateStreamTransition(
    const common::OperationAction action,
    const StreamOperationState currentState,
    StreamOperationState& nextState)
{
    handler::handler_utils::StreamOperation op{};
    if (action == handler::sign_handler_operations::SIGN_INIT)
    {
        op = handler::handler_utils::StreamOperation::kInit;
    }
    else if (action == handler::sign_handler_operations::SIGN_UPDATE)
    {
        op = handler::handler_utils::StreamOperation::kUpdate;
    }
    else if (action == handler::sign_handler_operations::SIGN_FINALIZE)
    {
        op = handler::handler_utils::StreamOperation::kFinalize;
    }
    else
    {
        return make_unexpected(DaemonErrorCode::kInvalidOperation);
    }
    const auto result = handler::handler_utils::ValidateStreamOperationSequence(currentState, op);
    if (!result.has_value())
    {
        return make_unexpected(result.error());
    }
    nextState = result.value();
    return std::monostate{};
}
}  // namespace score::crypto::daemon::provider::score_provider::operations::sign
