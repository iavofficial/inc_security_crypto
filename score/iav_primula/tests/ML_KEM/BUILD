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

# Adopted pqa_c smoke tests (M04).

cc_test(
    name = "smoke_ml_kem_1024_test",
    timeout = "moderate",
    srcs = ["ML_KEM_1024_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_kem_1024",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_ml_kem_1024_legacy_test",
    timeout = "long",
    srcs = ["ML_KEM_1024_legacy_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_kem_1024",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/ML_KEM:nist_fips203_testvectors",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "//score/iav_primula/tests/common:smoke_test_helpers",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_ml_kem_512_test",
    timeout = "moderate",
    srcs = ["ML_KEM_512_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_kem_512",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_ml_kem_512_legacy_test",
    timeout = "long",
    srcs = ["ML_KEM_512_legacy_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_kem_512",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/ML_KEM:nist_fips203_testvectors",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "//score/iav_primula/tests/common:smoke_test_helpers",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_ml_kem_768_test",
    timeout = "moderate",
    srcs = ["ML_KEM_768_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_kem_768",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_ml_kem_768_legacy_test",
    timeout = "long",
    srcs = ["ML_KEM_768_legacy_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:ml_kem_768",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/ML_KEM:nist_fips203_testvectors",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "//score/iav_primula/tests/common:smoke_test_helpers",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "nist_fips203_testvectors",
    testonly = True,
    srcs = [
        "ML_KEM_encapDecapFIPS203Tr1_testData.cpp",
        "ML_KEM_encapDecapFIPS203_testData.cpp",
        "ML_KEM_keyGenFIPS203_testData.cpp",
    ],
    hdrs = [
        "ML_KEM_encapDecapFIPS203Tr1_testData.h",
        "ML_KEM_encapDecapFIPS203_testData.h",
        "ML_KEM_keyGenFIPS203_testData.h",
    ],
    includes = ["."],
)
