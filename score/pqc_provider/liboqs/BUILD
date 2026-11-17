###############################################################################
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
###############################################################################

load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//visibility:private"])

cc_library(
    name = "_header_oqs",
    hdrs = ["src/oqs.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src",
)

cc_library(
    name = "_header_common",
    hdrs = ["src/common/common.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/common",
)

cc_library(
    name = "_header_rand",
    hdrs = ["src/common/rand/rand.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/common/rand",
)

cc_library(
    name = "_header_kem",
    hdrs = ["src/kem/kem.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/kem",
)

cc_library(
    name = "_header_sig",
    hdrs = ["src/sig/sig.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/sig",
)

cc_library(
    name = "_header_sig_stfl",
    hdrs = ["src/sig_stfl/sig_stfl.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/sig_stfl",
)

cc_library(
    name = "_header_aes_ops",
    hdrs = ["src/common/aes/aes_ops.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/common/aes",
)

cc_library(
    name = "_header_sha2_ops",
    hdrs = ["src/common/sha2/sha2_ops.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/common/sha2",
)

cc_library(
    name = "_header_sha3",
    hdrs = ["src/common/sha3/sha3.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/common/sha3",
)

cc_library(
    name = "_header_sha3x4",
    hdrs = ["src/common/sha3/sha3x4.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/common/sha3",
)

cc_library(
    name = "_header_sha3_ops",
    hdrs = ["src/common/sha3/sha3_ops.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/common/sha3",
)

cc_library(
    name = "_header_sha3x4_ops",
    hdrs = ["src/common/sha3/sha3x4_ops.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/common/sha3",
)

cc_library(
    name = "_header_ml_kem",
    hdrs = ["src/kem/ml_kem/kem_ml_kem.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/kem/ml_kem",
)

cc_library(
    name = "_header_ml_dsa",
    hdrs = ["src/sig/ml_dsa/sig_ml_dsa.h"],
    include_prefix = "oqs",
    strip_include_prefix = "src/sig/ml_dsa",
)

cc_library(
    name = "public_headers",
    deps = [
        ":_header_aes_ops",
        ":_header_common",
        ":_header_kem",
        ":_header_ml_dsa",
        ":_header_ml_kem",
        ":_header_oqs",
        ":_header_rand",
        ":_header_sha2_ops",
        ":_header_sha3",
        ":_header_sha3_ops",
        ":_header_sha3x4",
        ":_header_sha3x4_ops",
        ":_header_sig",
        ":_header_sig_stfl",
        "//score/pqc_provider:liboqs_config_header",
    ],
)

cc_library(
    name = "common_headers",
    hdrs = glob([
        "src/common/common.h",
        "src/common/pqclean_shims/fips202.h",
        "src/common/pqclean_shims/fips202x4.h",
        "src/common/rand/rand.h",
        "src/common/sha3/*.h",
        "src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/*.h",
        "src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/*.macros",
        "src/common/sha3/xkcp_low/KeccakP-1600times4/serial/*.h",
        "src/common/sha3/xkcp_low/KeccakP-1600times4/serial/*.inc",
    ]),
    includes = [
        "src/common/pqclean_shims",
        "src/common/sha3",
        "src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits",
    ],
    deps = [":public_headers"],
)

filegroup(
    name = "common_sources",
    srcs = [
        "src/common/common.c",
        "src/common/pqclean_shims/fips202.c",
        "src/common/pqclean_shims/fips202x4.c",
        "src/common/rand/rand.c",
        "src/common/sha3/sha3.c",
        "src/common/sha3/sha3x4.c",
        "src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.c",
        "src/common/sha3/xkcp_low/KeccakP-1600times4/serial/KeccakP-1600-times4-on1.c",
        "src/common/sha3/xkcp_sha3.c",
        "src/common/sha3/xkcp_sha3x4.c",
    ],
)

filegroup(
    name = "api_sources",
    srcs = [
        "src/kem/kem.c",
        "src/sig/sig.c",
    ],
)

cc_library(
    name = "ml_dsa_44_headers",
    hdrs = glob([
        "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/integration/liboqs/*.h",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/*.inc",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/*.h",
    ]),
    includes = [
        "src/common/pqclean_shims",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref",
    ],
    deps = [":public_headers"],
)

filegroup(
    name = "ml_dsa_44_sources",
    srcs = [
        "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/ct.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/debug.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/packing.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/poly.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/poly_kl.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/polyvec.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/polyvec_lazy.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/sign.c",
        "src/sig/ml_dsa/sig_ml_dsa_44.c",
    ],
)

cc_library(
    name = "ml_dsa_65_headers",
    hdrs = glob(
        [
            "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/integration/liboqs/*.h",
            "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/*.h",
            "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/*.inc",
        ],
        allow_empty = True,
    ),
    includes = [
        "src/common/pqclean_shims",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref",
    ],
    deps = [":public_headers"],
)

filegroup(
    name = "ml_dsa_65_sources",
    srcs = [
        "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/ct.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/debug.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/packing.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/poly.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/poly_kl.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/polyvec.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/polyvec_lazy.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/sign.c",
        "src/sig/ml_dsa/sig_ml_dsa_65.c",
    ],
)

cc_library(
    name = "ml_dsa_87_headers",
    hdrs = glob(
        [
            "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/integration/liboqs/*.h",
            "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/*.h",
            "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/*.inc",
        ],
        allow_empty = True,
    ),
    includes = [
        "src/common/pqclean_shims",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref",
    ],
    deps = [":public_headers"],
)

filegroup(
    name = "ml_dsa_87_sources",
    srcs = [
        "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/ct.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/debug.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/packing.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/poly.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/poly_kl.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/polyvec.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/polyvec_lazy.c",
        "src/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/sign.c",
        "src/sig/ml_dsa/sig_ml_dsa_87.c",
    ],
)

cc_library(
    name = "ml_kem_512_headers",
    hdrs = glob(
        [
            "src/kem/ml_kem/mlkem-native_ml-kem-512_ref/integration/liboqs/*.h",
            "src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/*.h",
            "src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/*.inc",
        ],
        allow_empty = True,
    ),
    includes = [
        "src/common/pqclean_shims",
        "src/kem/ml_kem/mlkem-native_ml-kem-512_ref",
    ],
    deps = [":public_headers"],
)

filegroup(
    name = "ml_kem_512_sources",
    srcs = [
        "src/kem/ml_kem/kem_ml_kem_512.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/compress.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/debug.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/indcpa.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/kem.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/poly.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/poly_k.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/sampling.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/verify.c",
    ],
)

cc_library(
    name = "ml_kem_768_headers",
    hdrs = glob(
        [
            "src/kem/ml_kem/mlkem-native_ml-kem-768_ref/integration/liboqs/*.h",
            "src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/*.h",
            "src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/*.inc",
        ],
        allow_empty = True,
    ),
    includes = [
        "src/common/pqclean_shims",
        "src/kem/ml_kem/mlkem-native_ml-kem-768_ref",
    ],
    deps = [":public_headers"],
)

filegroup(
    name = "ml_kem_768_sources",
    srcs = [
        "src/kem/ml_kem/kem_ml_kem_768.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/compress.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/debug.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/indcpa.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/kem.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/poly.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/poly_k.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/sampling.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/verify.c",
    ],
)

cc_library(
    name = "ml_kem_1024_headers",
    hdrs = glob(
        [
            "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/integration/liboqs/*.h",
            "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/*.h",
            "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/*.inc",
        ],
        allow_empty = True,
    ),
    includes = [
        "src/common/pqclean_shims",
        "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref",
    ],
    deps = [":public_headers"],
)

filegroup(
    name = "ml_kem_1024_sources",
    srcs = [
        "src/kem/ml_kem/kem_ml_kem_1024.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/compress.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/debug.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/indcpa.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/kem.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/poly.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/poly_k.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/sampling.c",
        "src/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/verify.c",
    ],
)

cc_library(
    name = "liboqs_common",
    srcs = [":common_sources"],
    deps = [
        ":common_headers",
        ":public_headers",
    ],
)

cc_library(
    name = "liboqs_ml_dsa_44",
    srcs = [":ml_dsa_44_sources"],
    copts = [
        "-DMLD_CONFIG_PARAMETER_SET=44",
        "-DMLD_CONFIG_FILE=\\\"../../integration/liboqs/config_c.h\\\"",
    ],
    deps = [
        ":liboqs_common",
        ":ml_dsa_44_headers",
        ":public_headers",
    ],
)

cc_library(
    name = "liboqs_ml_dsa_65",
    srcs = [":ml_dsa_65_sources"],
    copts = [
        "-DMLD_CONFIG_PARAMETER_SET=65",
        "-DMLD_CONFIG_FILE=\\\"../../integration/liboqs/config_c.h\\\"",
    ],
    deps = [
        ":liboqs_common",
        ":ml_dsa_65_headers",
        ":public_headers",
    ],
)

cc_library(
    name = "liboqs_ml_dsa_87",
    srcs = [":ml_dsa_87_sources"],
    copts = [
        "-DMLD_CONFIG_PARAMETER_SET=87",
        "-DMLD_CONFIG_FILE=\\\"../../integration/liboqs/config_c.h\\\"",
    ],
    deps = [
        ":liboqs_common",
        ":ml_dsa_87_headers",
        ":public_headers",
    ],
)

cc_library(
    name = "liboqs_ml_kem_512",
    srcs = [":ml_kem_512_sources"],
    copts = [
        "-DMLK_CONFIG_PARAMETER_SET=512",
        "-DMLK_CONFIG_FILE=\\\"../../integration/liboqs/config_c.h\\\"",
    ],
    deps = [
        ":liboqs_common",
        ":ml_kem_512_headers",
        ":public_headers",
    ],
)

cc_library(
    name = "liboqs_ml_kem_768",
    srcs = [":ml_kem_768_sources"],
    copts = [
        "-DMLK_CONFIG_PARAMETER_SET=768",
        "-DMLK_CONFIG_FILE=\\\"../../integration/liboqs/config_c.h\\\"",
    ],
    deps = [
        ":liboqs_common",
        ":ml_kem_768_headers",
        ":public_headers",
    ],
)

cc_library(
    name = "liboqs_ml_kem_1024",
    srcs = [":ml_kem_1024_sources"],
    copts = [
        "-DMLK_CONFIG_PARAMETER_SET=1024",
        "-DMLK_CONFIG_FILE=\\\"../../integration/liboqs/config_c.h\\\"",
    ],
    deps = [
        ":liboqs_common",
        ":ml_kem_1024_headers",
        ":public_headers",
    ],
)

cc_library(
    name = "liboqs_api",
    srcs = [":api_sources"],
    deps = [
        ":liboqs_common",
        ":liboqs_ml_dsa_44",
        ":liboqs_ml_dsa_65",
        ":liboqs_ml_dsa_87",
        ":liboqs_ml_kem_1024",
        ":liboqs_ml_kem_512",
        ":liboqs_ml_kem_768",
        ":public_headers",
    ],
)

cc_library(
    name = "liboqs_partial",
    visibility = [
        "//score/pqc_provider:__pkg__",
        "//score/pqc_provider/tests/upstream:__pkg__",
    ],
    deps = [":liboqs_api"],
)
