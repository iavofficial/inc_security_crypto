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

/// @file iav_primula_ffi.c
/// @brief Stable C ABI glue for the selected ML-DSA and ML-KEM APIs.

#include "score/iav_primula/include/iav_primula_ffi.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "ML_DSA_44_api.h"
#include "ML_DSA_65_api.h"
#include "ML_DSA_87_api.h"
#include "ML_KEM_1024_api.h"
#include "ML_KEM_512_api.h"
#include "ML_KEM_768_api.h"
#include "ML_KEM_api.h"
#include "iav_primula_rng_internal.h"
#include "score/iav_primula/include/Platform_Types.h"

typedef enum
{
    IavKeyFamilySignature = 1,
    IavKeyFamilyKem = 2
} iav_key_family;

typedef void (*iav_signature_keypair_fn)(uint8* public_key, uint8* secret_key);
typedef uint8 (*iav_signature_sign_fn)(uint8* signature,
                                       uint32* signature_len,
                                       const uint8* message,
                                       uint32 message_len,
                                       const uint8* secret_key);
typedef uint8 (*iav_signature_verify_fn)(const uint8* signature,
                                         uint32 signature_len,
                                         const uint8* message,
                                         uint32 message_len,
                                         const uint8* public_key);
typedef void (*iav_kem_keypair_fn)(uint8* public_key, uint8* secret_key);
typedef void (*iav_kem_encapsulate_fn)(uint8* ciphertext, uint8* shared_secret, const uint8* public_key);
typedef void (*iav_kem_decapsulate_fn)(uint8* shared_secret, const uint8* ciphertext, const uint8* secret_key);

typedef struct
{
    iav_algorithm algorithm;
    iav_key_family family;
    size_t public_key_size;
    size_t secret_key_size;
    size_t signature_size;
    size_t ciphertext_size;
    size_t shared_secret_size;
    iav_signature_keypair_fn signature_keypair;
    iav_signature_sign_fn signature_sign;
    iav_signature_verify_fn signature_verify;
    iav_kem_keypair_fn kem_keypair;
    iav_kem_encapsulate_fn kem_encapsulate;
    iav_kem_decapsulate_fn kem_decapsulate;
} iav_algorithm_descriptor;

struct iav_primula_key_handle
{
    iav_algorithm algorithm;
    iav_key_family family;
    size_t public_key_size;
    size_t secret_key_size;
    size_t allocation_size;
    uint8 key_material[];
};

static const iav_algorithm_descriptor g_iav_algorithms[] = {
    {
        .algorithm = IavAlgorithmMlDsa44,
        .family = IavKeyFamilySignature,
        .public_key_size = FSMSW_ML_DSA_44_CRYPTO_PUBLICKEYBYTES,
        .secret_key_size = FSMSW_ML_DSA_44_CRYPTO_SECRETKEYBYTES,
        .signature_size = FSMSW_ML_DSA_44_CRYPTO_BYTES,
        .signature_keypair = ML_DSA_44_Crypto_Sign_KeyPair,
        .signature_sign = ML_DSA_44_Crypto_Sign_Signature,
        .signature_verify = ML_DSA_44_Crypto_Sign_Verify,
    },
    {
        .algorithm = IavAlgorithmMlDsa65,
        .family = IavKeyFamilySignature,
        .public_key_size = FSMSW_ML_DSA_65_CRYPTO_PUBLICKEYBYTES,
        .secret_key_size = FSMSW_ML_DSA_65_CRYPTO_SECRETKEYBYTES,
        .signature_size = FSMSW_ML_DSA_65_CRYPTO_BYTES,
        .signature_keypair = ML_DSA_65_Crypto_Sign_KeyPair,
        .signature_sign = ML_DSA_65_Crypto_Sign_Signature,
        .signature_verify = ML_DSA_65_Crypto_Sign_Verify,
    },
    {
        .algorithm = IavAlgorithmMlDsa87,
        .family = IavKeyFamilySignature,
        .public_key_size = FSMSW_ML_DSA_87_CRYPTO_PUBLICKEYBYTES,
        .secret_key_size = FSMSW_ML_DSA_87_CRYPTO_SECRETKEYBYTES,
        .signature_size = FSMSW_ML_DSA_87_CRYPTO_BYTES,
        .signature_keypair = ML_DSA_87_Crypto_Sign_KeyPair,
        .signature_sign = ML_DSA_87_Crypto_Sign_Signature,
        .signature_verify = ML_DSA_87_Crypto_Sign_Verify,
    },
    {
        .algorithm = IavAlgorithmMlKem512,
        .family = IavKeyFamilyKem,
        .public_key_size = ML_KEM_512_PUBLICKEYBYTES,
        .secret_key_size = ML_KEM_512_SECRETKEYBYTES,
        .ciphertext_size = ML_KEM_512_CIPHERTEXTBYTES,
        .shared_secret_size = ML_KEM_SSBYTES,
        .kem_keypair = ML_KEM_512_Crypto_Kem_KeyPair,
        .kem_encapsulate = ML_KEM_512_Crypto_Kem_Enc,
        .kem_decapsulate = ML_KEM_512_Crypto_Kem_Dec,
    },
    {
        .algorithm = IavAlgorithmMlKem768,
        .family = IavKeyFamilyKem,
        .public_key_size = ML_KEM_768_PUBLICKEYBYTES,
        .secret_key_size = ML_KEM_768_SECRETKEYBYTES,
        .ciphertext_size = ML_KEM_768_CIPHERTEXTBYTES,
        .shared_secret_size = ML_KEM_SSBYTES,
        .kem_keypair = ML_KEM_768_Crypto_Kem_KeyPair,
        .kem_encapsulate = ML_KEM_768_Crypto_Kem_Enc,
        .kem_decapsulate = ML_KEM_768_Crypto_Kem_Dec,
    },
    {
        .algorithm = IavAlgorithmMlKem1024,
        .family = IavKeyFamilyKem,
        .public_key_size = ML_KEM_1024_PUBLICKEYBYTES,
        .secret_key_size = ML_KEM_1024_SECRETKEYBYTES,
        .ciphertext_size = ML_KEM_1024_CIPHERTEXTBYTES,
        .shared_secret_size = ML_KEM_SSBYTES,
        .kem_keypair = ML_KEM_1024_Crypto_Kem_KeyPair,
        .kem_encapsulate = ML_KEM_1024_Crypto_Kem_Enc,
        .kem_decapsulate = ML_KEM_1024_Crypto_Kem_Dec,
    },
};

static const uint8 g_iav_empty_message = 0U;

static void iav_copy_bytes(uint8_t* dest, const uint8_t* src, size_t length)
{
    size_t index = 0U;

    for (index = 0U; index < length; ++index)
    {
        dest[index] = src[index];
    }
}

static const iav_algorithm_descriptor* iav_find_algorithm(iav_algorithm algorithm)
{
    size_t index = 0U;

    for (index = 0U; index < (sizeof(g_iav_algorithms) / sizeof(g_iav_algorithms[0])); ++index)
    {
        if (g_iav_algorithms[index].algorithm == algorithm)
        {
            return &g_iav_algorithms[index];
        }
    }

    return NULL;
}

static bool iav_is_signature_algorithm(iav_algorithm algorithm)
{
    switch (algorithm)
    {
        case IavAlgorithmMlDsa44:
        case IavAlgorithmMlDsa65:
        case IavAlgorithmMlDsa87:
        case IavAlgorithmFnDsa512:
        case IavAlgorithmFnDsa1024:
        case IavAlgorithmSlhDsaSha2_128f:
        case IavAlgorithmSlhDsaSha2_128s:
        case IavAlgorithmSlhDsaSha2_192f:
        case IavAlgorithmSlhDsaSha2_192s:
        case IavAlgorithmSlhDsaSha2_256f:
        case IavAlgorithmSlhDsaSha2_256s:
        case IavAlgorithmSlhDsaShake128f:
        case IavAlgorithmSlhDsaShake128s:
        case IavAlgorithmSlhDsaShake192f:
        case IavAlgorithmSlhDsaShake192s:
        case IavAlgorithmSlhDsaShake256f:
        case IavAlgorithmSlhDsaShake256s:
            return true;
        default:
            return false;
    }
}

static bool iav_is_kem_algorithm(iav_algorithm algorithm)
{
    switch (algorithm)
    {
        case IavAlgorithmMlKem512:
        case IavAlgorithmMlKem768:
        case IavAlgorithmMlKem1024:
        case IavAlgorithmHqc128:
        case IavAlgorithmHqc192:
        case IavAlgorithmHqc256:
            return true;
        default:
            return false;
    }
}

static iav_status iav_lookup_algorithm(iav_algorithm algorithm,
                                       iav_key_family requested_family,
                                       const iav_algorithm_descriptor** descriptor)
{
    const iav_algorithm_descriptor* found = iav_find_algorithm(algorithm);

    if (found != NULL)
    {
        if (found->family != requested_family)
        {
            return IavStatusInvalidArgument;
        }
        *descriptor = found;
        return IavStatusOk;
    }

    if ((requested_family == IavKeyFamilySignature && iav_is_kem_algorithm(algorithm)) ||
        (requested_family == IavKeyFamilyKem && iav_is_signature_algorithm(algorithm)))
    {
        return IavStatusInvalidArgument;
    }

    return IavStatusUnsupportedAlgorithm;
}

static iav_primula_key_handle* iav_key_create(const iav_algorithm_descriptor* descriptor)
{
    size_t key_bytes = 0U;
    size_t allocation_size = 0U;
    iav_primula_key_handle* key = NULL;

    if (descriptor->public_key_size > SIZE_MAX - descriptor->secret_key_size)
    {
        return NULL;
    }
    key_bytes = descriptor->public_key_size + descriptor->secret_key_size;
    if (key_bytes > SIZE_MAX - sizeof(*key))
    {
        return NULL;
    }
    allocation_size = sizeof(*key) + key_bytes;

    key = (iav_primula_key_handle*)calloc(1U, allocation_size);
    if (key == NULL)
    {
        return NULL;
    }

    key->algorithm = descriptor->algorithm;
    key->family = descriptor->family;
    key->public_key_size = descriptor->public_key_size;
    key->secret_key_size = descriptor->secret_key_size;
    key->allocation_size = allocation_size;
    return key;
}

static void iav_key_release(iav_primula_key_handle* key)
{
    if (key != NULL)
    {
        const size_t allocation_size = key->allocation_size;
        iav_primula_secure_clear(key, allocation_size);
        free(key);
    }
}

static const iav_algorithm_descriptor* iav_validate_key(const iav_primula_key_handle* key,
                                                        iav_key_family expected_family)
{
    const iav_algorithm_descriptor* descriptor = NULL;
    size_t expected_allocation_size = 0U;
    size_t key_bytes = 0U;

    if (key == NULL || key->family != expected_family)
    {
        return NULL;
    }

    descriptor = iav_find_algorithm(key->algorithm);
    if (descriptor == NULL || descriptor->family != expected_family ||
        descriptor->public_key_size != key->public_key_size || descriptor->secret_key_size != key->secret_key_size ||
        descriptor->public_key_size > SIZE_MAX - descriptor->secret_key_size)
    {
        return NULL;
    }

    key_bytes = descriptor->public_key_size + descriptor->secret_key_size;
    if (key_bytes > SIZE_MAX - sizeof(*key))
    {
        return NULL;
    }
    expected_allocation_size = sizeof(*key) + key_bytes;
    if (expected_allocation_size != key->allocation_size)
    {
        return NULL;
    }

    return descriptor;
}

static iav_status iav_generate_keypair(iav_algorithm algorithm,
                                       iav_key_family requested_family,
                                       iav_primula_key_handle** key_output)
{
    const iav_algorithm_descriptor* descriptor = NULL;
    iav_primula_key_handle* key = NULL;
    iav_status status = IavStatusCryptoFailure;
    bool rng_succeeded = false;

    if (key_output == NULL)
    {
        return IavStatusInvalidArgument;
    }
    *key_output = NULL;

    status = iav_lookup_algorithm(algorithm, requested_family, &descriptor);
    if (status != IavStatusOk)
    {
        return status;
    }

    key = iav_key_create(descriptor);
    if (key == NULL)
    {
        return IavStatusCryptoFailure;
    }

    if (!iav_primula_rng_operation_begin())
    {
        iav_key_release(key);
        return IavStatusCryptoFailure;
    }

    if (requested_family == IavKeyFamilySignature)
    {
        descriptor->signature_keypair(key->key_material, &key->key_material[key->public_key_size]);
    }
    else
    {
        descriptor->kem_keypair(key->key_material, &key->key_material[key->public_key_size]);
    }
    rng_succeeded = iav_primula_rng_operation_end();

    if (!rng_succeeded)
    {
        iav_key_release(key);
        return IavStatusCryptoFailure;
    }

    *key_output = key;
    return IavStatusOk;
}

static bool iav_ranges_overlap(const void* first, size_t first_size, const void* second, size_t second_size)
{
    const uintptr_t first_address = (uintptr_t)first;
    const uintptr_t second_address = (uintptr_t)second;

    if (first_size == 0U || second_size == 0U)
    {
        return false;
    }

    if (first_address <= second_address)
    {
        return (second_address - first_address) < (uintptr_t)first_size;
    }

    return (first_address - second_address) < (uintptr_t)second_size;
}

iav_status iav_keypair_generate(iav_algorithm algorithm, iav_primula_key_handle** key)
{
    return iav_generate_keypair(algorithm, IavKeyFamilySignature, key);
}

iav_status iav_public_key_export(const iav_primula_key_handle* key, uint8_t* output, size_t* output_len)
{
    const iav_algorithm_descriptor* descriptor = NULL;
    const size_t output_capacity = output_len != NULL ? *output_len : 0U;

    if (output_len == NULL)
    {
        return IavStatusInvalidArgument;
    }
    descriptor = iav_validate_key(key, IavKeyFamilySignature);
    if (descriptor == NULL)
    {
        return IavStatusInvalidArgument;
    }
    if (output_capacity < descriptor->public_key_size)
    {
        *output_len = descriptor->public_key_size;
        return IavStatusBufferTooSmall;
    }
    if (output == NULL)
    {
        return IavStatusInvalidArgument;
    }

    iav_copy_bytes(output, key->key_material, descriptor->public_key_size);
    *output_len = descriptor->public_key_size;
    return IavStatusOk;
}

iav_status iav_sign(const iav_primula_key_handle* key,
                    const uint8_t* message,
                    size_t message_len,
                    uint8_t* signature,
                    size_t* signature_len)
{
    const iav_algorithm_descriptor* descriptor = NULL;
    const uint8_t* safe_message = message;
    const size_t signature_capacity = signature_len != NULL ? *signature_len : 0U;
    uint8_t* temporary_signature = NULL;
    uint32 actual_signature_len = 0U;
    uint8 vendor_status = 1U;

    if (signature_len == NULL || message_len > UINT32_MAX || (message == NULL && message_len != 0U))
    {
        return IavStatusInvalidArgument;
    }
    descriptor = iav_validate_key(key, IavKeyFamilySignature);
    if (descriptor == NULL)
    {
        return IavStatusInvalidArgument;
    }
    if (signature_capacity < descriptor->signature_size)
    {
        *signature_len = descriptor->signature_size;
        return IavStatusBufferTooSmall;
    }
    if (signature == NULL)
    {
        return IavStatusInvalidArgument;
    }
    if (safe_message == NULL)
    {
        safe_message = &g_iav_empty_message;
    }

    temporary_signature = (uint8_t*)malloc(descriptor->signature_size);
    if (temporary_signature == NULL)
    {
        return IavStatusCryptoFailure;
    }

    vendor_status = descriptor->signature_sign(temporary_signature,
                                               &actual_signature_len,
                                               safe_message,
                                               (uint32)message_len,
                                               &key->key_material[key->public_key_size]);
    if (vendor_status != 0U || actual_signature_len != descriptor->signature_size)
    {
        iav_primula_secure_clear(temporary_signature, descriptor->signature_size);
        free(temporary_signature);
        return IavStatusCryptoFailure;
    }

    iav_copy_bytes(signature, temporary_signature, actual_signature_len);
    *signature_len = actual_signature_len;
    iav_primula_secure_clear(temporary_signature, descriptor->signature_size);
    free(temporary_signature);
    return IavStatusOk;
}

iav_status iav_verify(const iav_primula_key_handle* key,
                      const uint8_t* message,
                      size_t message_len,
                      const uint8_t* signature,
                      size_t signature_len)
{
    const iav_algorithm_descriptor* descriptor = NULL;
    const uint8_t* safe_message = message;
    uint8 vendor_status = 1U;

    if (message_len > UINT32_MAX || (message == NULL && message_len != 0U) || signature == NULL)
    {
        return IavStatusInvalidArgument;
    }
    descriptor = iav_validate_key(key, IavKeyFamilySignature);
    if (descriptor == NULL)
    {
        return IavStatusInvalidArgument;
    }
    if (signature_len != descriptor->signature_size)
    {
        return IavStatusInvalidArgument;
    }
    if (safe_message == NULL)
    {
        safe_message = &g_iav_empty_message;
    }

    vendor_status = descriptor->signature_verify(
        signature, (uint32)signature_len, safe_message, (uint32)message_len, key->key_material);
    return vendor_status == 0U ? IavStatusOk : IavStatusVerificationFailed;
}

iav_status iav_kem_keypair_generate(iav_algorithm algorithm, iav_primula_key_handle** key)
{
    return iav_generate_keypair(algorithm, IavKeyFamilyKem, key);
}

iav_status iav_kem_public_key_export(const iav_primula_key_handle* key, uint8_t* output, size_t* output_len)
{
    const iav_algorithm_descriptor* descriptor = NULL;
    const size_t output_capacity = output_len != NULL ? *output_len : 0U;

    if (output_len == NULL)
    {
        return IavStatusInvalidArgument;
    }
    descriptor = iav_validate_key(key, IavKeyFamilyKem);
    if (descriptor == NULL)
    {
        return IavStatusInvalidArgument;
    }
    if (output_capacity < descriptor->public_key_size)
    {
        *output_len = descriptor->public_key_size;
        return IavStatusBufferTooSmall;
    }
    if (output == NULL)
    {
        return IavStatusInvalidArgument;
    }

    iav_copy_bytes(output, key->key_material, descriptor->public_key_size);
    *output_len = descriptor->public_key_size;
    return IavStatusOk;
}

iav_status iav_kem_encapsulate(iav_algorithm algorithm,
                               const uint8_t* public_key,
                               size_t public_key_len,
                               uint8_t* ciphertext,
                               size_t* ciphertext_len,
                               uint8_t* shared_secret,
                               size_t* shared_secret_len)
{
    const iav_algorithm_descriptor* descriptor = NULL;
    uint8_t* temporary_shared_secret = NULL;
    uint8_t* temporary_outputs = NULL;
    size_t temporary_outputs_size = 0U;
    size_t ciphertext_capacity = 0U;
    size_t shared_secret_capacity = 0U;
    bool rng_succeeded = false;
    iav_status status = IavStatusCryptoFailure;

    if (ciphertext_len == NULL || shared_secret_len == NULL ||
        iav_ranges_overlap(ciphertext_len, sizeof(*ciphertext_len), shared_secret_len, sizeof(*shared_secret_len)))
    {
        return IavStatusInvalidArgument;
    }

    status = iav_lookup_algorithm(algorithm, IavKeyFamilyKem, &descriptor);
    if (status != IavStatusOk)
    {
        return status;
    }
    if (public_key == NULL || public_key_len != descriptor->public_key_size)
    {
        return IavStatusInvalidArgument;
    }

    ciphertext_capacity = *ciphertext_len;
    shared_secret_capacity = *shared_secret_len;
    if (ciphertext_capacity < descriptor->ciphertext_size || shared_secret_capacity < descriptor->shared_secret_size)
    {
        *ciphertext_len = descriptor->ciphertext_size;
        *shared_secret_len = descriptor->shared_secret_size;
        return IavStatusBufferTooSmall;
    }
    if (ciphertext == NULL || shared_secret == NULL ||
        iav_ranges_overlap(ciphertext, descriptor->ciphertext_size, shared_secret, descriptor->shared_secret_size))
    {
        return IavStatusInvalidArgument;
    }

    if (descriptor->ciphertext_size > SIZE_MAX - descriptor->shared_secret_size)
    {
        return IavStatusCryptoFailure;
    }
    temporary_outputs_size = descriptor->ciphertext_size + descriptor->shared_secret_size;
    temporary_outputs = (uint8_t*)malloc(temporary_outputs_size);
    if (temporary_outputs == NULL)
    {
        return IavStatusCryptoFailure;
    }
    temporary_shared_secret = &temporary_outputs[descriptor->ciphertext_size];

    if (!iav_primula_rng_operation_begin())
    {
        iav_primula_secure_clear(temporary_outputs, temporary_outputs_size);
        free(temporary_outputs);
        return IavStatusCryptoFailure;
    }

    descriptor->kem_encapsulate(temporary_outputs, temporary_shared_secret, public_key);
    rng_succeeded = iav_primula_rng_operation_end();
    if (!rng_succeeded)
    {
        iav_primula_secure_clear(temporary_outputs, temporary_outputs_size);
        free(temporary_outputs);
        return IavStatusCryptoFailure;
    }

    iav_copy_bytes(ciphertext, temporary_outputs, descriptor->ciphertext_size);
    iav_copy_bytes(shared_secret, temporary_shared_secret, descriptor->shared_secret_size);
    *ciphertext_len = descriptor->ciphertext_size;
    *shared_secret_len = descriptor->shared_secret_size;
    iav_primula_secure_clear(temporary_outputs, temporary_outputs_size);
    free(temporary_outputs);
    return IavStatusOk;
}

iav_status iav_kem_decapsulate(const iav_primula_key_handle* key,
                               const uint8_t* ciphertext,
                               size_t ciphertext_len,
                               uint8_t* shared_secret,
                               size_t* shared_secret_len)
{
    const iav_algorithm_descriptor* descriptor = NULL;
    const size_t shared_secret_capacity = shared_secret_len != NULL ? *shared_secret_len : 0U;
    uint8_t temporary_shared_secret[ML_KEM_SSBYTES] = {0U};

    if (ciphertext == NULL || shared_secret_len == NULL)
    {
        return IavStatusInvalidArgument;
    }
    descriptor = iav_validate_key(key, IavKeyFamilyKem);
    if (descriptor == NULL)
    {
        return IavStatusInvalidArgument;
    }
    if (ciphertext_len != descriptor->ciphertext_size)
    {
        return IavStatusInvalidArgument;
    }
    if (shared_secret_capacity < descriptor->shared_secret_size)
    {
        *shared_secret_len = descriptor->shared_secret_size;
        return IavStatusBufferTooSmall;
    }
    if (shared_secret == NULL || descriptor->shared_secret_size > sizeof(temporary_shared_secret))
    {
        return IavStatusInvalidArgument;
    }

    descriptor->kem_decapsulate(temporary_shared_secret, ciphertext, &key->key_material[key->public_key_size]);
    iav_copy_bytes(shared_secret, temporary_shared_secret, descriptor->shared_secret_size);
    *shared_secret_len = descriptor->shared_secret_size;
    iav_primula_secure_clear(temporary_shared_secret, sizeof(temporary_shared_secret));
    return IavStatusOk;
}

void iav_key_destroy(iav_primula_key_handle* key)
{
    iav_key_release(key);
}
