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

/// @file iav_primula_ffi.h
/// @brief Stable C ABI between the C++ daemon and the Rust PQC backend.

#ifndef SCORE_IAV_PRIMULA_FFI_H
#define SCORE_IAV_PRIMULA_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum iav_status
{
    IAV_STATUS_OK = 0,
    IAV_STATUS_INVALID_ARGUMENT = 1,
    IAV_STATUS_BUFFER_TOO_SMALL = 2,
    IAV_STATUS_UNSUPPORTED_ALGORITHM = 3,
    IAV_STATUS_VERIFICATION_FAILED = 4,
    IAV_STATUS_CRYPTO_FAILURE = 5
} iav_status;

typedef enum iav_algorithm
{
    IAV_ALGORITHM_ML_DSA_44 = 1,
    IAV_ALGORITHM_ML_DSA_65 = 2,
    IAV_ALGORITHM_ML_DSA_87 = 3,
    IAV_ALGORITHM_ML_KEM_512 = 10,
    IAV_ALGORITHM_ML_KEM_768 = 11,
    IAV_ALGORITHM_ML_KEM_1024 = 12
} iav_algorithm;

typedef struct iav_primula_key_handle iav_primula_key_handle;

iav_status iav_keypair_generate(iav_algorithm algorithm, iav_primula_key_handle** key);
iav_status iav_public_key_export(const iav_primula_key_handle* key, uint8_t* output, size_t* output_len);
iav_status iav_kem_keypair_generate(iav_algorithm algorithm, iav_primula_key_handle** key);
iav_status iav_kem_public_key_export(const iav_primula_key_handle* key, uint8_t* output, size_t* output_len);
iav_status iav_sign(const iav_primula_key_handle* key,
                    const uint8_t* message,
                    size_t message_len,
                    uint8_t* signature,
                    size_t* signature_len);
iav_status iav_verify(const iav_primula_key_handle* key,
                      const uint8_t* message,
                      size_t message_len,
                      const uint8_t* signature,
                      size_t signature_len);
iav_status iav_kem_encapsulate(iav_algorithm algorithm,
                                const uint8_t* public_key,
                                size_t public_key_len,
                                uint8_t* ciphertext,
                                size_t* ciphertext_len,
                                uint8_t* shared_secret,
                                size_t* shared_secret_len);
iav_status iav_kem_decapsulate(const iav_primula_key_handle* key,
                                const uint8_t* ciphertext,
                                size_t ciphertext_len,
                                uint8_t* shared_secret,
                                size_t* shared_secret_len);
void iav_key_destroy(iav_primula_key_handle* key);

#ifdef __cplusplus
}
#endif

#endif  // SCORE_IAV_PRIMULA_FFI_H
