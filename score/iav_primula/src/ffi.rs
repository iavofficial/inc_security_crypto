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

//! C ABI boundary for the iavPrimula PQC backend.
//!
//! The cryptographic implementations are intentionally not exposed as C++
//! types. This module owns the opaque Rust key handle and translates all
//! failures to stable `iav_status` values.

use core::ffi::c_void;

#[repr(C)]
pub struct iav_primula_key_handle {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum iav_status {
    IAV_STATUS_OK = 0,
    IAV_STATUS_INVALID_ARGUMENT = 1,
    IAV_STATUS_BUFFER_TOO_SMALL = 2,
    IAV_STATUS_UNSUPPORTED_ALGORITHM = 3,
    IAV_STATUS_VERIFICATION_FAILED = 4,
    IAV_STATUS_CRYPTO_FAILURE = 5,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum iav_algorithm {
    IAV_ALGORITHM_ML_DSA_44 = 1,
    IAV_ALGORITHM_ML_DSA_65 = 2,
    IAV_ALGORITHM_ML_DSA_87 = 3,
    IAV_ALGORITHM_ML_KEM_512 = 10,
    IAV_ALGORITHM_ML_KEM_768 = 11,
    IAV_ALGORITHM_ML_KEM_1024 = 12,
}

fn unsupported() -> iav_status {
    iav_status::IAV_STATUS_UNSUPPORTED_ALGORITHM
}

#[no_mangle]
pub extern "C" fn iav_keypair_generate(
    _algorithm: iav_algorithm,
    _key: *mut *mut iav_primula_key_handle,
) -> iav_status {
    unsupported()
}

#[no_mangle]
pub extern "C" fn iav_public_key_export(
    _key: *const iav_primula_key_handle,
    _output: *mut u8,
    _output_len: *mut usize,
) -> iav_status {
    unsupported()
}

#[no_mangle]
pub extern "C" fn iav_kem_keypair_generate(
    _algorithm: iav_algorithm,
    _key: *mut *mut iav_primula_key_handle,
) -> iav_status {
    unsupported()
}

#[no_mangle]
pub extern "C" fn iav_kem_public_key_export(
    _key: *const iav_primula_key_handle,
    _output: *mut u8,
    _output_len: *mut usize,
) -> iav_status {
    unsupported()
}

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

#[no_mangle]
pub extern "C" fn iav_key_destroy(_key: *mut iav_primula_key_handle) {}

#[allow(dead_code)]
fn _opaque_pointer_marker(_: *const c_void) {}
