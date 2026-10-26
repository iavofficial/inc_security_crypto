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

# Adopted pqa_c module tests (M03).

cc_test(
    name = "module_hqc128_parsing_test",
    timeout = "moderate",
    srcs = ["HQC_128_parsing_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:hqc_128",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_hqc128_vector_test",
    timeout = "moderate",
    srcs = ["HQC_128_vector_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:hqc_128",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_hqc192_parsing_test",
    timeout = "moderate",
    srcs = ["HQC_192_parsing_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:hqc_192",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_hqc192_vector_test",
    timeout = "moderate",
    srcs = ["HQC_192_vector_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:hqc_192",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_hqc256_parsing_test",
    timeout = "moderate",
    srcs = ["HQC_256_parsing_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:hqc_256",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_hqc256_vector_test",
    timeout = "moderate",
    srcs = ["HQC_256_vector_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:hqc_256",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

# Adopted pqa_c smoke tests (M04).

cc_test(
    name = "smoke_hqc128_test",
    timeout = "moderate",
    srcs = ["HQC_128_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:hqc_128",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_hqc192_test",
    timeout = "moderate",
    srcs = ["HQC_192_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:hqc_192",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_hqc256_test",
    timeout = "moderate",
    srcs = ["HQC_256_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:hqc_256",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)
