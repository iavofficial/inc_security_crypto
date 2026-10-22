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

#include "TEST_Helpers.h"

#include <cctype>

namespace
{

int HexCharToValue(char value)
{
    if (value >= '0' && value <= '9')
    {
        return value - '0';
    }
    value = static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
    if (value >= 'a' && value <= 'f')
    {
        return 10 + value - 'a';
    }
    return 0;
}

}  // namespace

uint8_t* hexStringToUint8Array(const std::string& hex, std::size_t& out_len)
{
    if (hex.size() % 2U != 0U)
    {
        return nullptr;
    }

    out_len = hex.size() / 2U;
    auto* const bytes = new uint8_t[out_len];
    for (std::size_t index = 0U; index < out_len; ++index)
    {
        const char high = hex[2U * index];
        const char low = hex[2U * index + 1U];
        if (std::isxdigit(static_cast<unsigned char>(high)) == 0 || std::isxdigit(static_cast<unsigned char>(low)) == 0)
        {
            delete[] bytes;
            return nullptr;
        }
        bytes[index] = static_cast<uint8_t>((HexCharToValue(high) << 4) | HexCharToValue(low));
    }
    return bytes;
}
