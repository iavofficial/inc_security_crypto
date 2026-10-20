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
