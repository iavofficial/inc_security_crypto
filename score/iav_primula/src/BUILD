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

load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "iav_primula_impl",
    srcs = ["iav_primula_ffi.c"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    implementation_deps = ["//score/iav_primula:vendor_headers"],
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
    deps = [
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:ml_dsa",
        "//score/iav_primula:ml_kem",
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula/src/Libs:commonlib_adapter",
    ],
)

alias(
    name = "iav_primula",
    actual = ":iav_primula_impl",
    visibility = ["//score/iav_primula:__pkg__"],
)

alias(
    name = "iav_primula_staticlib",
    actual = ":iav_primula_impl",
    visibility = ["//score/iav_primula:__pkg__"],
)

cc_library(
    name = "headers",
    hdrs = ["Std_Types.h"],
    includes = ["."],
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)
