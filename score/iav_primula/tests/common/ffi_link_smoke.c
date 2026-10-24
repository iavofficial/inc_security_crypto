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

/// @file ffi_link_smoke.c
/// @brief Link-check the C FFI archive and its selected Automotive dependencies.

#include "score/iav_primula/include/iav_primula_ffi.h"

#include <stddef.h>

int main(void)
{
    iav_primula_key_handle* key = NULL;

    if (iav_keypair_generate(IavAlgorithmMlDsa44, &key) != IavStatusCryptoFailure)
    {
        return 1;
    }
    if (key != NULL)
    {
        return 1;
    }

    if (iav_keypair_generate(IavAlgorithmMlKem512, &key) != IavStatusInvalidArgument)
    {
        return 1;
    }
    if (key != NULL)
    {
        return 1;
    }

    return 0;
}
