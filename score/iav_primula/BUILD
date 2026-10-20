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

alias(
    name = "iav_primula",
    actual = "//score/iav_primula/src:iav_primula",
    visibility = ["//visibility:public"],
)

alias(
    name = "iav_primula_staticlib",
    actual = "//score/iav_primula/src:iav_primula_staticlib",
    visibility = ["//visibility:public"],
)

cc_library(
    name = "iav_primula_ffi_headers",
    hdrs = ["include/iav_primula_ffi.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "primula_platform_types",
    hdrs = ["include/Platform_Types.h"],
    includes = ["include"],
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

# Header-only targets below src/ retain the vendor tree's package structure.
# This private aggregate gives implementation targets and the API smoke test
# access to all headers without exposing vendor headers as public API.
cc_library(
    name = "vendor_headers",
    visibility = ["//score/iav_primula:__subpackages__"],
    deps = [
        "//score/iav_primula/src:headers",
        "//score/iav_primula/src/FN_DSA:headers",
        "//score/iav_primula/src/FN_DSA/FN_DSA_1024:headers",
        "//score/iav_primula/src/FN_DSA/FN_DSA_512:headers",
        "//score/iav_primula/src/FN_DSA/common:headers",
        "//score/iav_primula/src/Hqc:headers",
        "//score/iav_primula/src/Hqc/Hqc128:headers",
        "//score/iav_primula/src/Hqc/Hqc192:headers",
        "//score/iav_primula/src/Hqc/Hqc256:headers",
        "//score/iav_primula/src/Libs:headers",
        "//score/iav_primula/src/ML_DSA:headers",
        "//score/iav_primula/src/ML_DSA/ML_DSA_44:headers",
        "//score/iav_primula/src/ML_DSA/ML_DSA_65:headers",
        "//score/iav_primula/src/ML_DSA/ML_DSA_87:headers",
        "//score/iav_primula/src/ML_DSA/common:headers",
        "//score/iav_primula/src/ML_KEM:headers",
        "//score/iav_primula/src/ML_KEM/ML_KEM_1024:headers",
        "//score/iav_primula/src/ML_KEM/ML_KEM_512:headers",
        "//score/iav_primula/src/ML_KEM/ML_KEM_768:headers",
        "//score/iav_primula/src/ML_KEM/common:headers",
        "//score/iav_primula/src/SLH_DSA:headers",
        "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHA2_128fSimple:headers",
        "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHA2_128sSimple:headers",
        "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHA2_192fSimple:headers",
        "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHA2_192sSimple:headers",
        "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHA2_256fSimple:headers",
        "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHA2_256sSimple:headers",
        "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHAKE_128fSimple:headers",
        "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHAKE_128sSimple:headers",
        "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHAKE_192fSimple:headers",
        "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHAKE_192sSimple:headers",
        "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHAKE_256fSimple:headers",
        "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHAKE_256sSimple:headers",
        "//score/iav_primula/src/SLH_DSA/common:headers",
    ],
)

# Shared and per-family targets are kept in this package so consumers do not
# need a separate //score/primula package just to reach the C libraries.

alias(
    name = "fips202",
    actual = "//score/iav_primula/src/Libs:fips202",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "sha2",
    actual = "//score/iav_primula/src/Libs:sha2",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "fn_dsa_common",
    actual = "//score/iav_primula/src/FN_DSA/common:fn_dsa_common",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "ml_dsa_common",
    actual = "//score/iav_primula/src/ML_DSA/common:ml_dsa_common",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "ml_kem_common",
    actual = "//score/iav_primula/src/ML_KEM/common:ml_kem_common",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_common",
    actual = "//score/iav_primula/src/SLH_DSA/common:slh_dsa_common",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "fn_dsa_512",
    actual = "//score/iav_primula/src/FN_DSA/FN_DSA_512:fn_dsa_512",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "fn_dsa_1024",
    actual = "//score/iav_primula/src/FN_DSA/FN_DSA_1024:fn_dsa_1024",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "hqc_128",
    actual = "//score/iav_primula/src/Hqc/Hqc128:hqc_128",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "hqc_192",
    actual = "//score/iav_primula/src/Hqc/Hqc192:hqc_192",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "hqc_256",
    actual = "//score/iav_primula/src/Hqc/Hqc256:hqc_256",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "ml_dsa_44",
    actual = "//score/iav_primula/src/ML_DSA/ML_DSA_44:ml_dsa_44",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "ml_dsa_65",
    actual = "//score/iav_primula/src/ML_DSA/ML_DSA_65:ml_dsa_65",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "ml_dsa_87",
    actual = "//score/iav_primula/src/ML_DSA/ML_DSA_87:ml_dsa_87",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "ml_kem_512",
    actual = "//score/iav_primula/src/ML_KEM/ML_KEM_512:ml_kem_512",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "ml_kem_768",
    actual = "//score/iav_primula/src/ML_KEM/ML_KEM_768:ml_kem_768",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "ml_kem_1024",
    actual = "//score/iav_primula/src/ML_KEM/ML_KEM_1024:ml_kem_1024",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_sha2_128f",
    actual = "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHA2_128fSimple:slh_dsa_sha2_128f",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_sha2_128s",
    actual = "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHA2_128sSimple:slh_dsa_sha2_128s",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_sha2_192f",
    actual = "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHA2_192fSimple:slh_dsa_sha2_192f",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_sha2_192s",
    actual = "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHA2_192sSimple:slh_dsa_sha2_192s",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_sha2_256f",
    actual = "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHA2_256fSimple:slh_dsa_sha2_256f",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_sha2_256s",
    actual = "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHA2_256sSimple:slh_dsa_sha2_256s",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_shake_128f",
    actual = "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHAKE_128fSimple:slh_dsa_shake_128f",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_shake_128s",
    actual = "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHAKE_128sSimple:slh_dsa_shake_128s",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_shake_192f",
    actual = "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHAKE_192fSimple:slh_dsa_shake_192f",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_shake_192s",
    actual = "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHAKE_192sSimple:slh_dsa_shake_192s",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_shake_256f",
    actual = "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHAKE_256fSimple:slh_dsa_shake_256f",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

alias(
    name = "slh_dsa_shake_256s",
    actual = "//score/iav_primula/src/SLH_DSA/SLH_DSA_SHAKE_256sSimple:slh_dsa_shake_256s",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
)

# FFI currently covers ML-DSA-44/65/87 and ML-KEM-512/768/1024. Other
# families are buildable; ABI exposure and glue are handled in M02.

cc_library(
    name = "shared_support",
    visibility = [
        "//tools/coverage:__pkg__",
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
    deps = [
        ":fips202",
        ":sha2",
    ],
)

cc_library(
    name = "fn_dsa",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
    deps = [
        ":fn_dsa_1024",
        ":fn_dsa_512",
    ],
)

cc_library(
    name = "hqc",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
    deps = [
        ":hqc_128",
        ":hqc_192",
        ":hqc_256",
    ],
)

cc_library(
    name = "ml_dsa",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
    deps = [
        ":ml_dsa_44",
        ":ml_dsa_65",
        ":ml_dsa_87",
    ],
)

cc_library(
    name = "ml_kem",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
    deps = [
        ":ml_kem_1024",
        ":ml_kem_512",
        ":ml_kem_768",
    ],
)

cc_library(
    name = "slh_dsa",
    visibility = [
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
    deps = [
        ":slh_dsa_sha2_128f",
        ":slh_dsa_sha2_128s",
        ":slh_dsa_sha2_192f",
        ":slh_dsa_sha2_192s",
        ":slh_dsa_sha2_256f",
        ":slh_dsa_sha2_256s",
        ":slh_dsa_shake_128f",
        ":slh_dsa_shake_128s",
        ":slh_dsa_shake_192f",
        ":slh_dsa_shake_192s",
        ":slh_dsa_shake_256f",
        ":slh_dsa_shake_256s",
    ],
)

cc_library(
    name = "primula",
    visibility = [
        "//tools/coverage:__pkg__",
        "//score/iav_primula:__pkg__",
        "//score/iav_primula:__subpackages__",
    ],
    deps = [
        ":fn_dsa",
        ":hqc",
        ":ml_dsa",
        ":ml_kem",
        ":slh_dsa",
    ],
)
