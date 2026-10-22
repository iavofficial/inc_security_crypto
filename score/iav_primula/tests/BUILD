# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

test_suite(
    name = "ffi_test",
    tests = [
        "//score/iav_primula/tests/FN_DSA:fn_dsa_attached_message_test",
        "//score/iav_primula/tests/FN_DSA:fn_dsa_codec_boundary_test",
        "//score/iav_primula/tests/FN_DSA:fn_dsa_malformed_encoding_test",
        "//score/iav_primula/tests/FN_DSA:fn_dsa_malformed_header_test",
        "//score/iav_primula/tests/FN_DSA:fn_dsa_optional_keygen_output_test",
        "//score/iav_primula/tests/FN_DSA:fn_dsa_primitive_boundary_test",
        "//score/iav_primula/tests/Libs:shared_hash_extension_test",
        "//score/iav_primula/tests/Libs:shared_primitive_test",
        "//score/iav_primula/tests/ML_DSA:ml_dsa_context_api_test",
        "//score/iav_primula/tests/ML_DSA:ml_dsa_malformed_signature_test",
        "//score/iav_primula/tests/SLH_DSA:slh_dsa_attached_message_test",
        "//score/iav_primula/tests/common:direct_family_functional_test",
        "//score/iav_primula/tests/common:ffi_algorithm_family_boundary_test",
        "//score/iav_primula/tests/common:functional_ffi_test",
        "//score/iav_primula/tests/common:rng_unconfigured_ffi_test",
    ],
    visibility = ["//tests/iav_primula:__pkg__"],
)

test_suite(
    name = "module_test",
    tests = [
        "//score/iav_primula/tests/FN_DSA:module_fn_dsa_1024_codec_test",
        "//score/iav_primula/tests/FN_DSA:module_fn_dsa_1024_pqclean_test",
        "//score/iav_primula/tests/FN_DSA:module_fn_dsa_512_codec_test",
        "//score/iav_primula/tests/FN_DSA:module_fn_dsa_512_pqclean_test",
        "//score/iav_primula/tests/Hqc:module_hqc128_parsing_test",
        "//score/iav_primula/tests/Hqc:module_hqc128_vector_test",
        "//score/iav_primula/tests/Hqc:module_hqc192_parsing_test",
        "//score/iav_primula/tests/Hqc:module_hqc192_vector_test",
        "//score/iav_primula/tests/Hqc:module_hqc256_parsing_test",
        "//score/iav_primula/tests/Hqc:module_hqc256_vector_test",
        "//score/iav_primula/tests/ML_DSA:module_ml_dsa_44_packing_test",
        "//score/iav_primula/tests/ML_DSA:module_ml_dsa_44_poly_test",
        "//score/iav_primula/tests/ML_DSA:module_ml_dsa_44_rounding_test",
        "//score/iav_primula/tests/ML_DSA:module_ml_dsa_44_sign_test",
        "//score/iav_primula/tests/ML_DSA:module_ml_dsa_65_packing_test",
        "//score/iav_primula/tests/ML_DSA:module_ml_dsa_65_poly_test",
        "//score/iav_primula/tests/ML_DSA:module_ml_dsa_65_rounding_test",
        "//score/iav_primula/tests/ML_DSA:module_ml_dsa_65_sign_test",
        "//score/iav_primula/tests/ML_DSA:module_ml_dsa_87_packing_test",
        "//score/iav_primula/tests/ML_DSA:module_ml_dsa_87_poly_test",
        "//score/iav_primula/tests/ML_DSA:module_ml_dsa_87_rounding_test",
        "//score/iav_primula/tests/ML_DSA:module_ml_dsa_87_sign_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_sha2_128fsimple_hash_sha2_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_sha2_128fsimple_sign_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_sha2_128ssimple_hash_sha2_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_sha2_128ssimple_sign_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_sha2_192fsimple_hash_sha2_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_sha2_192fsimple_sign_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_sha2_192ssimple_hash_sha2_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_sha2_192ssimple_sign_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_sha2_256fsimple_hash_sha2_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_sha2_256fsimple_sign_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_sha2_256ssimple_hash_sha2_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_sha2_256ssimple_sign_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_shake_128fsimple_sign_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_shake_128ssimple_sign_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_shake_192fsimple_sign_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_shake_192ssimple_sign_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_shake_256fsimple_sign_test",
        "//score/iav_primula/tests/SLH_DSA:module_slh_dsa_shake_256ssimple_sign_test",
    ],
    visibility = ["//tests/iav_primula:__pkg__"],
)
