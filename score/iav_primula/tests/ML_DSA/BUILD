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
