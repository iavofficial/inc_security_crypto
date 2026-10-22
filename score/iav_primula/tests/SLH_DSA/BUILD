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
    name = "slh_dsa_attached_message_test",
    timeout = "moderate",
    srcs = ["slh_dsa_attached_message_test.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:iav_primula_staticlib",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:coverage_test_support",
        "@googletest//:gtest_main",
    ],
)

# Adopted pqa_c module tests (M03).

cc_test(
    name = "module_slh_dsa_sha2_128fsimple_hash_sha2_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHA2_128fSimple_hash_sha2.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_128f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_sha2_128fsimple_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHA2_128fSimple_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_128f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_sha2_128ssimple_hash_sha2_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHA2_128sSimple_hash_sha2.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_128s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_sha2_128ssimple_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHA2_128sSimple_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_128s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_sha2_192fsimple_hash_sha2_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHA2_192fSimple_hash_sha2.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_192f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_sha2_192fsimple_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHA2_192fSimple_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_192f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_sha2_192ssimple_hash_sha2_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHA2_192sSimple_hash_sha2.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_192s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_sha2_192ssimple_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHA2_192sSimple_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_192s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_sha2_256fsimple_hash_sha2_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHA2_256fSimple_hash_sha2.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_256f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_sha2_256fsimple_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHA2_256fSimple_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_256f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_sha2_256ssimple_hash_sha2_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHA2_256sSimple_hash_sha2.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_256s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_sha2_256ssimple_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHA2_256sSimple_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_256s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_shake_128fsimple_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHAKE_128fSimple_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_shake_128f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_shake_128ssimple_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHAKE_128sSimple_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_shake_128s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_shake_192fsimple_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHAKE_192fSimple_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_shake_192f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_shake_192ssimple_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHAKE_192sSimple_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_shake_192s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_shake_256fsimple_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHAKE_256fSimple_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_shake_256f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "module_slh_dsa_shake_256ssimple_sign_test",
    timeout = "moderate",
    srcs = ["M_TEST_SLH_DSA_SHAKE_256sSimple_sign.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_shake_256s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

# Adopted pqa_c smoke tests (M04).

cc_test(
    name = "smoke_slh_dsa_sha2_128fsimple_test",
    timeout = "moderate",
    srcs = ["TEST_SLH_DSA_SHA2_128fSimple.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_128f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_slh_dsa_sha2_128ssimple_test",
    timeout = "moderate",
    srcs = ["TEST_SLH_DSA_SHA2_128sSimple.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_128s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_slh_dsa_sha2_192fsimple_test",
    timeout = "moderate",
    srcs = ["TEST_SLH_DSA_SHA2_192fSimple.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_192f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_slh_dsa_sha2_192ssimple_test",
    timeout = "moderate",
    srcs = ["TEST_SLH_DSA_SHA2_192sSimple.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_192s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_slh_dsa_sha2_256fsimple_test",
    timeout = "moderate",
    srcs = ["TEST_SLH_DSA_SHA2_256fSimple.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_256f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_slh_dsa_sha2_256ssimple_test",
    timeout = "moderate",
    srcs = ["TEST_SLH_DSA_SHA2_256sSimple.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_sha2_256s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_slh_dsa_shake_128fsimple_test",
    timeout = "moderate",
    srcs = ["TEST_SLH_DSA_SHAKE_128fSimple.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_shake_128f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_slh_dsa_shake_128ssimple_test",
    timeout = "moderate",
    srcs = ["TEST_SLH_DSA_SHAKE_128sSimple.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_shake_128s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_slh_dsa_shake_192fsimple_test",
    timeout = "moderate",
    srcs = ["TEST_SLH_DSA_SHAKE_192fSimple.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_shake_192f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_slh_dsa_shake_192ssimple_test",
    timeout = "moderate",
    srcs = ["TEST_SLH_DSA_SHAKE_192sSimple.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_shake_192s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_slh_dsa_shake_256fsimple_test",
    timeout = "moderate",
    srcs = ["TEST_SLH_DSA_SHAKE_256fSimple.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_shake_256f",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "smoke_slh_dsa_shake_256ssimple_test",
    timeout = "moderate",
    srcs = ["TEST_SLH_DSA_SHAKE_256sSimple.cpp"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    deps = [
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula:slh_dsa_shake_256s",
        "//score/iav_primula:vendor_headers",
        "//score/iav_primula/src/Libs:commonlib_adapter",
        "//score/iav_primula/tests/common:crc32",
        "//score/iav_primula/tests/common:module_test_support",
        "@googletest//:gtest_main",
    ],
)
