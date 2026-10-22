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

load("@rules_cc//cc:cc_test.bzl", "cc_test")

package(default_visibility = ["//score/iav_primula/tests:__pkg__"])

cc_test(
    name = "ml_dsa_malformed_signature_test",
    timeout = "moderate",
    srcs = ["ml_dsa_malformed_signature_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "ml_dsa_context_api_test",
    timeout = "moderate",
    srcs = ["ml_dsa_context_api_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
        "//score/iav_primula:ml_dsa",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:coverage_test_support",
        "@googletest//:gtest_main",
    ],
)

# Adopted pqa_c module tests (M03).

cc_test(
    name = "module_ml_dsa_44_packing_test",
    timeout = "moderate",
    srcs = ["M_TEST_ML_DSA_44_packing.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_44",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_ml_dsa_44_poly_test",
    timeout = "moderate",
    srcs = ["M_TEST_ML_DSA_44_poly.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_44",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_ml_dsa_44_rounding_test",
    timeout = "moderate",
    srcs = ["M_TEST_ML_DSA_44_rounding.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_44",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_ml_dsa_44_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_ML_DSA_44_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_44",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_ml_dsa_65_packing_test",
    timeout = "moderate",
    srcs = ["M_TEST_ML_DSA_65_packing.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_65",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_ml_dsa_65_poly_test",
    timeout = "moderate",
    srcs = ["M_TEST_ML_DSA_65_poly.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_65",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_ml_dsa_65_rounding_test",
    timeout = "moderate",
    srcs = ["M_TEST_ML_DSA_65_rounding.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_65",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_ml_dsa_65_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_ML_DSA_65_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_65",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_ml_dsa_87_packing_test",
    timeout = "moderate",
    srcs = ["M_TEST_ML_DSA_87_packing.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_87",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_ml_dsa_87_poly_test",
    timeout = "moderate",
    srcs = ["M_TEST_ML_DSA_87_poly.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_87",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_ml_dsa_87_rounding_test",
    timeout = "moderate",
    srcs = ["M_TEST_ML_DSA_87_rounding.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_87",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_ml_dsa_87_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_ML_DSA_87_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_87",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

# Adopted pqa_c smoke tests (M04).

cc_test(
    name = "smoke_ml_dsa_44_test",
    timeout = "moderate",
    srcs = ["TEST_ML_DSA_44.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_44",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_ml_dsa_44_nist_test",
    timeout = "long",
    srcs = ["TEST_ML_DSA_44_Nist.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_44",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/ML_DSA:nist_fips204_testvectors",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "//score/iav_primula/tests/common:smoke_test_helpers",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_ml_dsa_65_test",
    timeout = "moderate",
    srcs = ["TEST_ML_DSA_65.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_65",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_ml_dsa_65_nist_test",
    timeout = "long",
    srcs = ["TEST_ML_DSA_65_Nist.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_65",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/ML_DSA:nist_fips204_testvectors",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "//score/iav_primula/tests/common:smoke_test_helpers",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_ml_dsa_87_test",
    timeout = "moderate",
    srcs = ["TEST_ML_DSA_87.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_87",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_ml_dsa_87_nist_test",
    timeout = "long",
    srcs = ["TEST_ML_DSA_87_Nist.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_dsa_87",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/ML_DSA:nist_fips204_testvectors",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "//score/iav_primula/tests/common:smoke_test_helpers",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "nist_fips204_testvectors",
    testonly = True,
    srcs = [
        "ML_DSA_keyGen_FIPS204_TestData.cpp",
        "ML_DSA_sigGen_FIPS204_TestData.cpp",
        "ML_DSA_sigGen_FIPS204_tr1_TestData.cpp",
        "ML_DSA_sigVer_FIPS204_TestData.cpp",
    ],
    hdrs = [
        "ML_DSA_keyGen_FIPS204_TestData.h",
        "ML_DSA_sigGen_FIPS204_TestData.h",
        "ML_DSA_sigGen_FIPS204_tr1_TestData.h",
        "ML_DSA_sigVer_FIPS204_TestData.h",
    ],
    includes = ["."],
)
