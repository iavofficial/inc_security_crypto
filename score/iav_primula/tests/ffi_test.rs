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

use iav_primula::{
    iav_algorithm, iav_key_destroy, iav_keypair_generate, iav_kem_decapsulate,
    iav_kem_encapsulate, iav_kem_keypair_generate, iav_kem_public_key_export,
    iav_public_key_export, iav_sign, iav_status, iav_verify,
    iav_primula_key_handle,
};

#[test]
fn exported_operations_report_unsupported_until_backend_is_connected() {
    // These are minimal placeholder values for the current stub operations:
    // key remains null, length is a dummy size parameter, and byte provides a
    // minimal message or data reference.
    let mut key: *mut iav_primula_key_handle = core::ptr::null_mut();
    let mut length = 0usize;
    let byte = 0u8;

    // Signature key management must return the stable unsupported status while
    // the concrete implementation is not integrated.
    assert_eq!(
        iav_keypair_generate(iav_algorithm::IAV_ALGORITHM_ML_DSA_44, &mut key),
        iav_status::IAV_STATUS_UNSUPPORTED_ALGORITHM
    );

    assert_eq!(
        iav_public_key_export(key, core::ptr::null_mut(), &mut length),
        iav_status::IAV_STATUS_UNSUPPORTED_ALGORITHM
    );

    // KEM key management follows the same stub contract.
    assert_eq!(
        iav_kem_keypair_generate(iav_algorithm::IAV_ALGORITHM_ML_KEM_512, &mut key),
        iav_status::IAV_STATUS_UNSUPPORTED_ALGORITHM
    );
    assert_eq!(
        iav_kem_public_key_export(key, core::ptr::null_mut(), &mut length),
        iav_status::IAV_STATUS_UNSUPPORTED_ALGORITHM
    );

    // Signature operations use the same unsupported status until implemented.
    assert_eq!(
        iav_sign(key, &byte, 0, core::ptr::null_mut(), &mut length),
        iav_status::IAV_STATUS_UNSUPPORTED_ALGORITHM
    );
    assert_eq!(
        iav_verify(key, &byte, 0, &byte, 0),
        iav_status::IAV_STATUS_UNSUPPORTED_ALGORITHM
    );

    // KEM operations also remain unsupported in the current backend stub.
    assert_eq!(
        iav_kem_encapsulate(
            iav_algorithm::IAV_ALGORITHM_ML_KEM_512,
            &byte,
            0,
            core::ptr::null_mut(),
            &mut length,
            core::ptr::null_mut(),
            &mut length,
        ),
        iav_status::IAV_STATUS_UNSUPPORTED_ALGORITHM
    );
    assert_eq!(
        iav_kem_decapsulate(key, &byte, 0, core::ptr::null_mut(), &mut length),
        iav_status::IAV_STATUS_UNSUPPORTED_ALGORITHM
    );

    // Resource cleanup is intentionally a no-op for the current null/stub handle.
    iav_key_destroy(key);
}

#[test]
fn ffi_status_and_algorithm_values_are_stable() {
    // Status values are part of the stable C ABI.
    assert_eq!(iav_status::IAV_STATUS_OK as u32, 0);
    assert_eq!(iav_status::IAV_STATUS_INVALID_ARGUMENT as u32, 1);
    assert_eq!(iav_status::IAV_STATUS_BUFFER_TOO_SMALL as u32, 2);
    assert_eq!(iav_status::IAV_STATUS_UNSUPPORTED_ALGORITHM as u32, 3);
    assert_eq!(iav_status::IAV_STATUS_VERIFICATION_FAILED as u32, 4);
    assert_eq!(iav_status::IAV_STATUS_CRYPTO_FAILURE as u32, 5);

    // Algorithm values must match the #[repr(C)] declarations in the C header.
    assert_eq!(iav_algorithm::IAV_ALGORITHM_ML_DSA_44 as u32, 1);
    assert_eq!(iav_algorithm::IAV_ALGORITHM_ML_DSA_65 as u32, 2);
    assert_eq!(iav_algorithm::IAV_ALGORITHM_ML_DSA_87 as u32, 3);
    assert_eq!(iav_algorithm::IAV_ALGORITHM_ML_KEM_512 as u32, 10);
    assert_eq!(iav_algorithm::IAV_ALGORITHM_ML_KEM_768 as u32, 11);
    assert_eq!(iav_algorithm::IAV_ALGORITHM_ML_KEM_1024 as u32, 12);
}
