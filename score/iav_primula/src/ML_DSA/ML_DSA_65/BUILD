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

cc_library(
    name = "ml_dsa_65",
    srcs = glob(["*.c"]),
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
        "//score/iav_primula:primula_platform_types",
        "//score/iav_primula/src/ML_DSA/common:ml_dsa_common",
    ],
)
