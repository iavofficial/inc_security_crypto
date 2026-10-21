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
load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "api_header_smoke",
    testonly = True,
    srcs = ["api_header_smoke.c"],
    deps = [
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
    ],
)

cc_binary(
    name = "ffi_link_smoke",
    srcs = ["ffi_link_smoke.c"],
    deps = [
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
    ],
)

cc_test(
    name = "functional_ffi_test",
    timeout = "moderate",
    srcs = ["functional_ffi_test.cpp"],
    deps = [
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "rng_unconfigured_ffi_test",
    srcs = ["rng_unconfigured_ffi_test.cpp"],
    deps = [
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "fn_dsa_malformed_header_test",
    timeout = "moderate",
    srcs = ["fn_dsa_malformed_header_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:fn_dsa",
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "fn_dsa_codec_boundary_test",
    srcs = ["fn_dsa_codec_boundary_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:fn_dsa_common",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "fn_dsa_malformed_encoding_test",
    timeout = "moderate",
    srcs = ["fn_dsa_malformed_encoding_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:fn_dsa",
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "fn_dsa_optional_keygen_output_test",
    timeout = "moderate",
    srcs = ["fn_dsa_optional_keygen_output_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:fn_dsa_common",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "fn_dsa_primitive_boundary_test",
    srcs = ["fn_dsa_primitive_boundary_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:fn_dsa_common",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "@googletest//:gtest_main",
    ],
)

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
    name = "ffi_algorithm_family_boundary_test",
    srcs = ["ffi_algorithm_family_boundary_test.cpp"],
    deps = [
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "direct_family_functional_test",
    timeout = "moderate",
    srcs = ["direct_family_functional_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:fn_dsa",
        "//score/iav_primula:hqc",
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "shared_primitive_test",
    srcs = ["shared_primitive_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:shared_support",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "coverage_test_support",
    testonly = True,
    hdrs = ["coverage_test_support.h"],
    deps = ["//score/iav_primula:iav_primula_ffi_headers"],
)

cc_test(
    name = "fn_dsa_attached_message_test",
    timeout = "moderate",
    srcs = ["fn_dsa_attached_message_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        ":coverage_test_support",
        "//score/iav_primula:fn_dsa",
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "slh_dsa_attached_message_test",
    timeout = "moderate",
    srcs = ["slh_dsa_attached_message_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        ":coverage_test_support",
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "shared_hash_extension_test",
    srcs = ["shared_hash_extension_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:fips202",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:sha2",
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
        ":coverage_test_support",
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
        "//score/iav_primula:ml_dsa",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "@googletest//:gtest_main",
    ],
)
