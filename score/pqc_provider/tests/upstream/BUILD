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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@rules_python//python:defs.bzl", "py_binary")

package(default_visibility = ["//visibility:private"])

cc_library(
    name = "test_helpers",
    srcs = ["test_helpers.c"],
    hdrs = ["test_helpers.h"],
    deps = ["//score/pqc_provider/liboqs:liboqs_partial"],
)

cc_library(
    name = "tmp_store",
    srcs = ["tmp_store.c"],
    hdrs = ["tmp_store.h"],
    deps = ["//score/pqc_provider/liboqs:liboqs_partial"],
)

cc_test(
    name = "test_sha3",
    srcs = ["test_sha3.c"],
    deps = ["//score/pqc_provider/liboqs:liboqs_partial"],
)

cc_test(
    name = "test_algorithm_registry",
    srcs = ["test_algorithm_registry.c"],
    deps = ["//score/pqc_provider/liboqs:liboqs_partial"],
)

cc_test(
    name = "test_kem_ml_kem_512",
    srcs = ["test_kem.c"],
    args = ["ML-KEM-512"],
    deps = [
        ":test_helpers",
        "//score/pqc_provider/liboqs:liboqs_partial",
    ],
)

cc_test(
    name = "test_kem_ml_kem_768",
    srcs = ["test_kem.c"],
    args = ["ML-KEM-768"],
    deps = [
        ":test_helpers",
        "//score/pqc_provider/liboqs:liboqs_partial",
    ],
)

cc_test(
    name = "test_kem_ml_kem_1024",
    srcs = ["test_kem.c"],
    args = ["ML-KEM-1024"],
    deps = [
        ":test_helpers",
        "//score/pqc_provider/liboqs:liboqs_partial",
    ],
)

py_binary(
    name = "convert_acvp_mlkem_vectors",
    srcs = ["convert_acvp_mlkem_vectors.py"],
    main = "convert_acvp_mlkem_vectors.py",
)

genrule(
    name = "mlkem_acvp_vectors_tsv",
    srcs = [
        "vectors/acvp/ML-KEM-encapDecap-FIPS203-internalProjection.json",
        "vectors/acvp/ML-KEM-keyGen-FIPS203-internalProjection.json",
    ],
    outs = ["mlkem_acvp_vectors.tsv"],
    cmd = "$(location :convert_acvp_mlkem_vectors) " +
          "$(location vectors/acvp/ML-KEM-keyGen-FIPS203-internalProjection.json) " +
          "$(location vectors/acvp/ML-KEM-encapDecap-FIPS203-internalProjection.json) > $@",
    tools = [":convert_acvp_mlkem_vectors"],
)

cc_test(
    name = "test_kem_acvp_vectors",
    srcs = ["test_kem_acvp_vectors.c"],
    args = ["$(location :mlkem_acvp_vectors_tsv)"],
    data = [":mlkem_acvp_vectors_tsv"],
    deps = ["//score/pqc_provider/liboqs:liboqs_partial"],
)

py_binary(
    name = "convert_acvp_mldsa_vectors",
    srcs = ["convert_acvp_mldsa_vectors.py"],
    main = "convert_acvp_mldsa_vectors.py",
)

genrule(
    name = "mldsa_acvp_vectors_tsv",
    srcs = [
        "vectors/acvp/ML-DSA-keyGen-FIPS204-internalProjection.json",
        "vectors/acvp/ML-DSA-sigGen-FIPS204-internalProjection.json",
        "vectors/acvp/ML-DSA-sigVer-FIPS204-internalProjection.json",
    ],
    outs = ["mldsa_acvp_vectors.tsv"],
    cmd = "$(location :convert_acvp_mldsa_vectors) " +
          "$(location vectors/acvp/ML-DSA-keyGen-FIPS204-internalProjection.json) " +
          "$(location vectors/acvp/ML-DSA-sigGen-FIPS204-internalProjection.json) " +
          "$(location vectors/acvp/ML-DSA-sigVer-FIPS204-internalProjection.json) > $@",
    tools = [":convert_acvp_mldsa_vectors"],
)

cc_test(
    name = "test_sig_acvp_vectors",
    srcs = ["test_sig_acvp_vectors.c"],
    args = ["$(location :mldsa_acvp_vectors_tsv)"],
    data = [":mldsa_acvp_vectors_tsv"],
    deps = ["//score/pqc_provider/liboqs:liboqs_partial"],
)

cc_test(
    name = "test_sig_ml_dsa_44",
    srcs = ["test_sig.c"],
    args = ["ML-DSA-44"],
    deps = [
        ":test_helpers",
        "//score/pqc_provider/liboqs:liboqs_partial",
    ],
)

cc_test(
    name = "test_sig_ml_dsa_65",
    srcs = ["test_sig.c"],
    args = ["ML-DSA-65"],
    deps = [
        ":test_helpers",
        "//score/pqc_provider/liboqs:liboqs_partial",
    ],
)

cc_test(
    name = "test_sig_ml_dsa_87",
    srcs = ["test_sig.c"],
    args = ["ML-DSA-87"],
    deps = [
        ":test_helpers",
        "//score/pqc_provider/liboqs:liboqs_partial",
    ],
)

cc_test(
    name = "test_kem_mem",
    srcs = ["test_kem_mem.c"],
    deps = [
        ":test_helpers",
        ":tmp_store",
        "//score/pqc_provider/liboqs:liboqs_partial",
    ],
)

cc_test(
    name = "test_sig_mem",
    srcs = ["test_sig_mem.c"],
    deps = [
        ":tmp_store",
        "//score/pqc_provider/liboqs:liboqs_partial",
    ],
)
