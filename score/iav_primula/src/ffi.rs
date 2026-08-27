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

//! Rust side of the stable C ABI for the IAV-Primula PQC backend.
//!
//! Cryptographic implementation types are intentionally not exposed to C++.
//! This module owns the opaque Rust key handle and translates failures to
//! stable `iav_status` values. The cryptographic entry points currently use
//! placeholder implementations and return `IAV_STATUS_UNSUPPORTED_ALGORITHM`.

use core::ffi::c_void;

#[repr(C)]
/// Opaque key handle exposed through the C ABI.
///
/// The handle contents are private to Rust and must not be accessed by C++
/// callers.
pub struct iav_primula_key_handle {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Status codes exchanged through the C ABI.
///
/// The numeric values must remain synchronized with `iav_primula_ffi.h`.
pub enum iav_status {
    IAV_STATUS_OK = 0,                    // Operation completed successfully.
    IAV_STATUS_INVALID_ARGUMENT = 1,      // One or more arguments are invalid.
    IAV_STATUS_BUFFER_TOO_SMALL = 2,      // An output buffer cannot hold the result.
    IAV_STATUS_UNSUPPORTED_ALGORITHM = 3, // The requested algorithm is not supported.
    IAV_STATUS_VERIFICATION_FAILED = 4,  // Verification completed and the signature is invalid.
    IAV_STATUS_CRYPTO_FAILURE = 5,       // The backend failed during a cryptographic operation.
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Algorithms exchanged through the C ABI.
///
/// The numeric values must remain synchronized with `iav_primula_ffi.h`.
pub enum iav_algorithm {
    IAV_ALGORITHM_ML_DSA_44 = 1,   // ML-DSA-44 signature algorithm.
    IAV_ALGORITHM_ML_DSA_65 = 2,   // ML-DSA-65 signature algorithm.
    IAV_ALGORITHM_ML_DSA_87 = 3,   // ML-DSA-87 signature algorithm.
    IAV_ALGORITHM_ML_KEM_512 = 10, // ML-KEM-512 key-encapsulation algorithm.
    IAV_ALGORITHM_ML_KEM_768 = 11, // ML-KEM-768 key-encapsulation algorithm.
    IAV_ALGORITHM_ML_KEM_1024 = 12, // ML-KEM-1024 key-encapsulation algorithm.
}

/// Return the status used by the currently unimplemented backend operations.
fn unsupported() -> iav_status {
    iav_status::IAV_STATUS_UNSUPPORTED_ALGORITHM
}

// The `extern "C"` ABI and `no_mangle` attribute preserve the C-compatible
// calling convention and exported symbol names declared in iav_primula_ffi.h.

// ---------------------------------------------------------------------------
// Signature key management
// ---------------------------------------------------------------------------

/// Generate a signature key pair.
///
/// This entry point is currently a placeholder and returns
/// `IAV_STATUS_UNSUPPORTED_ALGORITHM`.
#[no_mangle]
pub extern "C" fn iav_keypair_generate(
    _algorithm: iav_algorithm,
    _key: *mut *mut iav_primula_key_handle,
) -> iav_status {
    unsupported()
}

/// Export a signature public key.
///
/// This entry point is currently a placeholder and returns
/// `IAV_STATUS_UNSUPPORTED_ALGORITHM`.
#[no_mangle]
pub extern "C" fn iav_public_key_export(
    _key: *const iav_primula_key_handle,
    _output: *mut u8,
    _output_len: *mut usize,
) -> iav_status {
    unsupported()
}

// ---------------------------------------------------------------------------
// KEM key management
// ---------------------------------------------------------------------------

/// Generate a KEM key pair.
///
/// This entry point is currently a placeholder and returns
/// `IAV_STATUS_UNSUPPORTED_ALGORITHM`.
#[no_mangle]
pub extern "C" fn iav_kem_keypair_generate(
    _algorithm: iav_algorithm,
    _key: *mut *mut iav_primula_key_handle,
) -> iav_status {
    unsupported()
}

/// Export a KEM public key.
///
/// This entry point is currently a placeholder and returns
/// `IAV_STATUS_UNSUPPORTED_ALGORITHM`.
#[no_mangle]
pub extern "C" fn iav_kem_public_key_export(
    _key: *const iav_primula_key_handle,
    _output: *mut u8,
    _output_len: *mut usize,
) -> iav_status {
    unsupported()
}

// ---------------------------------------------------------------------------
// Signature operations
// ---------------------------------------------------------------------------

/// Sign a message with a signature key.
///
/// This entry point is currently a placeholder and returns
/// `IAV_STATUS_UNSUPPORTED_ALGORITHM`.
#[no_mangle]
pub extern "C" fn iav_sign(
    _key: *const iav_primula_key_handle,
    _message: *const u8,
    _message_len: usize,
    _signature: *mut u8,
    _signature_len: *mut usize,
) -> iav_status {
    unsupported()
}

/// Verify a message signature.
///
/// This entry point is currently a placeholder and returns
/// `IAV_STATUS_UNSUPPORTED_ALGORITHM`.
#[no_mangle]
pub extern "C" fn iav_verify(
    _key: *const iav_primula_key_handle,
    _message: *const u8,
    _message_len: usize,
    _signature: *const u8,
    _signature_len: usize,
) -> iav_status {
    unsupported()
}

// ---------------------------------------------------------------------------
// KEM operations
// ---------------------------------------------------------------------------

/// Encapsulate a shared secret using a public KEM key.
///
/// This entry point is currently a placeholder and returns
/// `IAV_STATUS_UNSUPPORTED_ALGORITHM`.
#[no_mangle]
pub extern "C" fn iav_kem_encapsulate(
    _algorithm: iav_algorithm,
    _public_key: *const u8,
    _public_key_len: usize,
    _ciphertext: *mut u8,
    _ciphertext_len: *mut usize,
    _shared_secret: *mut u8,
    _shared_secret_len: *mut usize,
) -> iav_status {
    unsupported()
}

/// Decapsulate a shared secret using a private KEM key.
///
/// This entry point is currently a placeholder and returns
/// `IAV_STATUS_UNSUPPORTED_ALGORITHM`.
#[no_mangle]
pub extern "C" fn iav_kem_decapsulate(
    _key: *const iav_primula_key_handle,
    _ciphertext: *const u8,
    _ciphertext_len: usize,
    _shared_secret: *mut u8,
    _shared_secret_len: *mut usize,
) -> iav_status {
    unsupported()
}

// ---------------------------------------------------------------------------
// Resource cleanup
// ---------------------------------------------------------------------------

/// Destroy a key handle and release its backend resources.
#[no_mangle]
pub extern "C" fn iav_key_destroy(_key: *mut iav_primula_key_handle) {}

/// Keep the opaque pointer type referenced without exposing its representation.
#[allow(dead_code)]
fn _opaque_pointer_marker(_: *const c_void) {}
