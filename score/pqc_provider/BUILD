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
    name = "pqc_provider_ffi_headers",
    hdrs = ["include/pqc_provider_ffi.h"],
    includes = ["include"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "liboqs_config_header",
    hdrs = ["include/oqs/oqsconfig.h"],
    includes = ["include"],
    visibility = [
        "//score/pqc_provider:__pkg__",
        "//score/pqc_provider/liboqs:__pkg__",
    ],
)

cc_library(
    name = "pqc_provider",
    srcs = ["src/ffi.cpp"],
    visibility = ["//visibility:public"],
    deps = [
        ":pqc_provider_ffi_headers",
        "//score/pqc_provider/liboqs:liboqs_partial",
    ],
)
