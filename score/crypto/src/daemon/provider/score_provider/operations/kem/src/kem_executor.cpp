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

#include "score/crypto/src/daemon/provider/score_provider/operations/kem/kem_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/kem_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/kem/score_kem_handler.hpp"
namespace score::crypto::daemon::provider::score_provider::operations::kem
{
namespace ops = ::score::crypto::daemon::provider::handler::kem_handler_operations;
Expected<common::ResponseParameters, common::DaemonErrorCode> KemExecutor::Execute(
    ScoreKemHandler& h, const common::OperationIdentifier& id, common::RequestParameters& r)
{
    switch (id.operationAction)
    {
        case ops::KEM_KEYGEN:
            if (!r.empty()) return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
            return h.GenerateKeyPair();
        case ops::KEM_ENCAPSULATE:
            if (r.empty()) return make_unexpected(common::DaemonErrorCode::kInsufficientParameters);
            return h.Encapsulate(r[0]);
        case ops::KEM_DECAPSULATE:
            if (r.empty()) return make_unexpected(common::DaemonErrorCode::kInsufficientParameters);
            return h.Decapsulate(r[0]);
        case ops::KEM_RESET:
        {
            auto x = h.Reset();
            if (!x.has_value()) return make_unexpected(x.error());
            return {};
        }
        default:
            return make_unexpected(common::DaemonErrorCode::kInvalidOperation);
    }
}
}  // namespace score::crypto::daemon::provider::score_provider::operations::kem
