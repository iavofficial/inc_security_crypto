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
#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEY_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_KEY_HANDLER_HPP

#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/iav_primula/include/iav_primula_ffi.h"
#include <vector>

namespace score::crypto::daemon::provider::score_provider::iav_primula
{
class IavPrimulaKeyHandler final : public key_management::IKeyHandler
{
  public:
    IavPrimulaKeyHandler(iav_primula_key_handle* native_key,
                         std::vector<std::uint8_t> public_key,
                         const key_management::ProviderKeyHandle& handle) noexcept;
    ~IavPrimulaKeyHandler() override;
    IavPrimulaKeyHandler(const IavPrimulaKeyHandler&) = delete;
    IavPrimulaKeyHandler& operator=(const IavPrimulaKeyHandler&) = delete;
    [[nodiscard]] const key_management::ProviderKeyHandle& GetHandle() const noexcept override;
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Release() override;
    [[nodiscard]] Expected<key_management::SecureKeyBytes, common::DaemonErrorCode> Export() const override;
    [[nodiscard]] common::ProviderId GetProviderId() const noexcept override;
    [[nodiscard]] iav_primula_key_handle* GetNativeHandle() const noexcept { return m_native_key; }
    [[nodiscard]] const std::uint8_t* GetPublicKey(std::size_t& size) const noexcept;

  private:
    iav_primula_key_handle* m_native_key;
    std::vector<std::uint8_t> m_public_key;
    key_management::ProviderKeyHandle m_handle;
    bool m_released{false};
};
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula
#endif
