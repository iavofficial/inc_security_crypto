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
    name = "headers",
    hdrs = glob(["*.h"]),
    includes = ["."],
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

# FsmSw_CommonLib.c is intentionally excluded: its RandomBytes implementation
# is a deterministic LCG. The project-owned adapter supplies the memory helpers
# and routes random requests through the registered platform provider, failing
# closed when no provider is installed or a request fails.
cc_library(
    name = "commonlib_adapter",
    srcs = [
        "FsmSw_CommonLib_adapter.c",
        "iav_primula_rng.c",
    ],
    hdrs = ["iav_primula_rng_internal.h"],
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
        ":headers",
        "//score/iav_primula:iav_primula_ffi_headers",
        "//score/iav_primula:primula_platform_types",
    ],
)

cc_library(
    name = "fips202",
    srcs = ["FsmSw_Fips202.c"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    implementation_deps = ["//score/iav_primula:vendor_headers"],
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
    deps = ["//score/iav_primula:primula_platform_types"],
)

cc_library(
    name = "sha2",
    srcs = ["FsmSw_sha2.c"],
    copts = [
        "-include",
        "Platform_Types.h",
    ],
    implementation_deps = ["//score/iav_primula:vendor_headers"],
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
    deps = ["//score/iav_primula:primula_platform_types"],
)
