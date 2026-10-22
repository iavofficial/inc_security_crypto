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

package(default_visibility = ["//score/iav_primula/tests:__pkg__"])

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

cc_library(
    name = "coverage_test_support",
    testonly = True,
    hdrs = ["coverage_test_support.h"],
    visibility = ["//score/iav_primula/tests:__subpackages__"],
    deps = ["//score/iav_primula:iav_primula_ffi_headers"],
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

cc_library(
    name = "crc32",
    testonly = True,
    srcs = ["crc32.c"],
    hdrs = ["crc32.h"],
    includes = ["."],
    visibility = ["//score/iav_primula/tests:__subpackages__"],
)

cc_library(
    name = "module_test_support",
    testonly = True,
    srcs = ["module_test_support.cpp"],
    hdrs = [
        "fake_fips202.h",
        "fff_IAV.h",
        "fff_helper.hpp",
        "module_test_support.h",
    ],
    includes = ["."],
    visibility = ["//score/iav_primula/tests:__subpackages__"],
    deps = [
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "@googletest//:gtest",
    ],
    alwayslink = True,
)

cc_library(
    name = "smoke_test_helpers",
    testonly = True,
    srcs = ["TEST_Helpers.cpp"],
    hdrs = ["TEST_Helpers.h"],
    includes = ["."],
    visibility = ["//score/iav_primula/tests:__subpackages__"],
)
