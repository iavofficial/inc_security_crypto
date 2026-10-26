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
/// @brief Stable C ABI between C/C++ consumers and the PQC backend.

#ifndef SCORE_IAV_PRIMULA_FFI_H
#define SCORE_IAV_PRIMULA_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Status codes returned by the IAV-Primula C ABI.
///
/// The numeric values are part of the stable ABI and must not be changed.
typedef enum iav_status
{
    IavStatusOk = 0,                    ///< The operation completed successfully.
    IavStatusInvalidArgument = 1,       ///< One or more arguments are invalid.
    IavStatusBufferTooSmall = 2,        ///< An output buffer cannot hold the result.
    IavStatusUnsupportedAlgorithm = 3,  ///< The requested algorithm is not supported.
    IavStatusVerificationFailed = 4,    ///< Verification completed and the signature is invalid.
    IavStatusCryptoFailure = 5          ///< The backend failed to perform the cryptographic operation.
} iav_status;

/// @brief Algorithms understood by the IAV-Primula C ABI.
///
/// The numeric values are part of the stable ABI and must not be changed.
typedef enum iav_algorithm
{
    IavAlgorithmMlDsa44 = 1,           ///< ML-DSA-44 signature algorithm.
    IavAlgorithmMlDsa65 = 2,           ///< ML-DSA-65 signature algorithm.
    IavAlgorithmMlDsa87 = 3,           ///< ML-DSA-87 signature algorithm.
    IavAlgorithmMlKem512 = 10,         ///< ML-KEM-512 key-encapsulation algorithm.
    IavAlgorithmMlKem768 = 11,         ///< ML-KEM-768 key-encapsulation algorithm.
    IavAlgorithmMlKem1024 = 12,        ///< ML-KEM-1024 key-encapsulation algorithm.
    IavAlgorithmFnDsa512 = 13,         ///< FN-DSA-512 signature algorithm.
    IavAlgorithmFnDsa1024 = 14,        ///< FN-DSA-1024 signature algorithm.
    IavAlgorithmSlhDsaSha2_128f = 15,  ///< SLH-DSA-SHA2-128f signature algorithm.
    IavAlgorithmSlhDsaSha2_128s = 16,  ///< SLH-DSA-SHA2-128s signature algorithm.
    IavAlgorithmSlhDsaSha2_192f = 17,  ///< SLH-DSA-SHA2-192f signature algorithm.
    IavAlgorithmSlhDsaSha2_192s = 18,  ///< SLH-DSA-SHA2-192s signature algorithm.
    IavAlgorithmSlhDsaSha2_256f = 19,  ///< SLH-DSA-SHA2-256f signature algorithm.
    IavAlgorithmSlhDsaSha2_256s = 20,  ///< SLH-DSA-SHA2-256s signature algorithm.
    IavAlgorithmSlhDsaShake128f = 21,  ///< SLH-DSA-SHAKE-128f signature algorithm.
    IavAlgorithmSlhDsaShake128s = 22,  ///< SLH-DSA-SHAKE-128s signature algorithm.
    IavAlgorithmSlhDsaShake192f = 23,  ///< SLH-DSA-SHAKE-192f signature algorithm.
    IavAlgorithmSlhDsaShake192s = 24,  ///< SLH-DSA-SHAKE-192s signature algorithm.
    IavAlgorithmSlhDsaShake256f = 25,  ///< SLH-DSA-SHAKE-256f signature algorithm.
    IavAlgorithmSlhDsaShake256s = 26,  ///< SLH-DSA-SHAKE-256s signature algorithm.
    IavAlgorithmHqc128 = 27,           ///< HQC-128 key-encapsulation algorithm.
    IavAlgorithmHqc192 = 28,           ///< HQC-192 key-encapsulation algorithm.
    IavAlgorithmHqc256 = 29            ///< HQC-256 key-encapsulation algorithm.
} iav_algorithm;

/// @brief Opaque backend-owned key handle.
///
/// The handle contents are private to the backend and must not be inspected
/// or modified by callers. Handles returned by generation functions must be
/// released with iav_key_destroy(). A handle must not be destroyed while
/// another thread is using it.
typedef struct iav_primula_key_handle iav_primula_key_handle;

/// @brief Platform-provided cryptographically secure random-byte callback.
///
/// The callback must fill every requested byte and return zero only when the
/// complete request succeeds. It must support concurrent calls, must not call
/// back into the IAV-Primula API, and must not retain the output pointer. The
/// callback and its user data must remain valid for the lifetime of the
/// process.
typedef int (*iav_random_bytes_callback)(uint8_t* output, size_t output_len, void* user_data);

/// @brief Install the platform random-byte provider exactly once.
///
/// Call this during process initialization, before any key generation or KEM
/// encapsulation. There is deliberately no default or deterministic fallback.
///
/// @param callback Reviewed platform entropy provider.
/// @param user_data Opaque context passed to callback.
/// @return IavStatusOk when installed, IavStatusInvalidArgument for a null
///         callback or if a provider has already been installed.
iav_status iav_random_bytes_provider_register(iav_random_bytes_callback callback, void* user_data);

// ---------------------------------------------------------------------------
// Signature key management
// ---------------------------------------------------------------------------

/// @brief Generate a signature key pair.
///
/// @param algorithm Signature algorithm to use.
/// @param key Output pointer receiving the generated key handle.
/// @return IavStatusOk on success, IavStatusCryptoFailure if no platform RNG
///         is registered or entropy generation fails, or another error status.
iav_status iav_keypair_generate(iav_algorithm algorithm, iav_primula_key_handle** key);

/// @brief Export the public key associated with a signature key handle.
///
/// @param key Signature key handle owned by the caller.
/// @param output Caller-provided output buffer for the public key.
/// @param output_len Input buffer capacity and output length written.
/// @return IavStatusOk on success, IavStatusBufferTooSmall when the
///         output buffer is insufficient (the required size is written and
///         output is unchanged), or another error status.
iav_status iav_public_key_export(const iav_primula_key_handle* key, uint8_t* output, size_t* output_len);

// ---------------------------------------------------------------------------
// Signature operations
// ---------------------------------------------------------------------------

/// @brief Sign a message with a generated signature key.
///
/// @param key Signature key handle owned by the caller.
/// @param message Message data to sign.
/// @param message_len Number of bytes in message.
///         A null message is permitted only when message_len is zero.
///         The message length must fit in a uint32_t.
/// @param signature Caller-provided output buffer for the signature.
/// @param signature_len Input buffer capacity and output signature length.
/// @return IavStatusOk on success, IavStatusBufferTooSmall when the
///         signature buffer is insufficient (the maximum required size is
///         written and signature is unchanged), or another error status.
iav_status iav_sign(const iav_primula_key_handle* key,
                    const uint8_t* message,
                    size_t message_len,
                    uint8_t* signature,
                    size_t* signature_len);

/// @brief Verify a message signature.
///
/// @param key Signature key handle owned by the caller.
/// @param message Message data to verify.
/// @param message_len Number of bytes in message.
///         A null message is permitted only when message_len is zero.
///         The message length must fit in a uint32_t.
/// @param signature Signature to verify.
/// @param signature_len Number of bytes in signature.
/// @return IavStatusOk when the signature is valid,
///         IavStatusVerificationFailed when it is invalid, or another
///         error status when verification cannot be performed. Malformed
///         fixed-length signatures return IavStatusInvalidArgument.
iav_status iav_verify(const iav_primula_key_handle* key,
                      const uint8_t* message,
                      size_t message_len,
                      const uint8_t* signature,
                      size_t signature_len);

// ---------------------------------------------------------------------------
// KEM key management
// ---------------------------------------------------------------------------

/// @brief Generate a KEM key pair.
///
/// @param algorithm KEM algorithm to use.
/// @param key Output pointer receiving the generated key handle.
/// @return IavStatusOk on success, IavStatusCryptoFailure if no platform RNG
///         is registered or entropy generation fails, or another error status.
iav_status iav_kem_keypair_generate(iav_algorithm algorithm, iav_primula_key_handle** key);

/// @brief Export the public key associated with a KEM key handle.
///
/// @param key KEM key handle owned by the caller.
/// @param output Caller-provided output buffer for the public key.
/// @param output_len Input buffer capacity and output length written.
/// @return IavStatusOk on success, IavStatusBufferTooSmall when the
///         output buffer is insufficient (the required size is written and
///         output is unchanged), or another error status.
iav_status iav_kem_public_key_export(const iav_primula_key_handle* key, uint8_t* output, size_t* output_len);

// ---------------------------------------------------------------------------
// KEM operations
// ---------------------------------------------------------------------------

/// @brief Encapsulate a shared secret using a public KEM key.
///
/// @param algorithm KEM algorithm to use.
/// @param public_key Public key used for encapsulation.
/// @param public_key_len Number of bytes in public_key.
/// @param ciphertext Caller-provided output buffer for the ciphertext.
/// @param ciphertext_len Input capacity and output ciphertext length.
/// @param shared_secret Caller-provided output buffer for the shared secret.
/// @param shared_secret_len Input capacity and output shared-secret length.
///         If either output capacity is too small, both required lengths are
///         reported and neither output buffer is modified.
///         The ciphertext and shared-secret output spans must not overlap.
///         The two length pointers must refer to non-overlapping size_t objects.
/// @return IavStatusOk on success, IavStatusBufferTooSmall when an
///         output buffer is insufficient, IavStatusCryptoFailure if no
///         platform RNG is registered or entropy generation fails, or
///         IavStatusInvalidArgument for null/overlapping output parameters or
///         another error status.
iav_status iav_kem_encapsulate(iav_algorithm algorithm,
                               const uint8_t* public_key,
                               size_t public_key_len,
                               uint8_t* ciphertext,
                               size_t* ciphertext_len,
                               uint8_t* shared_secret,
                               size_t* shared_secret_len);

/// @brief Decapsulate a shared secret using a private KEM key.
///
/// @param key KEM key handle owned by the caller.
/// @param ciphertext Ciphertext to decapsulate.
/// @param ciphertext_len Number of bytes in ciphertext.
/// @param shared_secret Caller-provided output buffer for the shared secret.
/// @param shared_secret_len Input capacity and output shared-secret length.
/// @return IavStatusOk on success, IavStatusBufferTooSmall when the
///         output buffer is insufficient, or another error status.
///         ML-KEM invalid ciphertexts produce the algorithm's implicit
///         rejection secret and do not produce a separate validity status.
iav_status iav_kem_decapsulate(const iav_primula_key_handle* key,
                               const uint8_t* ciphertext,
                               size_t ciphertext_len,
                               uint8_t* shared_secret,
                               size_t* shared_secret_len);

// ---------------------------------------------------------------------------
// Resource cleanup
// ---------------------------------------------------------------------------

/// @brief Destroy a key handle and release its backend resources.
///
/// The handle must not be used after this function returns.
///
/// @param key Key handle previously returned by a key-generation function.
///        A null handle is accepted as a no-op.
void iav_key_destroy(iav_primula_key_handle* key);

#ifdef __cplusplus
}
#endif

#endif  // SCORE_IAV_PRIMULA_FFI_H
