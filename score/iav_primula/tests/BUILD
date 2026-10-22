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
