/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

/// @file ffi_algorithm_family_boundary_test.cpp
/// @brief Tests FFI classification of recognized and unknown algorithm IDs.

#include "score/iav_primula/include/iav_primula_ffi.h"

#include <gtest/gtest.h>

#include <array>

namespace
{

// M04 P2 FFI classification gap: every recognized signature identifier must
// be rejected as a KEM with InvalidArgument, and vice versa. An unknown ID is
// not a cross-family mistake and must remain UnsupportedAlgorithm.
TEST(FfiAlgorithmFamilyBoundaryTest, ClassifiesKnownFamiliesAndUnknownIdentifiers)
{
    constexpr std::array<iav_algorithm, 17U> kSignatureAlgorithms = {
        IavAlgorithmMlDsa44,
        IavAlgorithmMlDsa65,
        IavAlgorithmMlDsa87,
        IavAlgorithmFnDsa512,
        IavAlgorithmFnDsa1024,
        IavAlgorithmSlhDsaSha2_128f,
        IavAlgorithmSlhDsaSha2_128s,
        IavAlgorithmSlhDsaSha2_192f,
        IavAlgorithmSlhDsaSha2_192s,
        IavAlgorithmSlhDsaSha2_256f,
        IavAlgorithmSlhDsaSha2_256s,
        IavAlgorithmSlhDsaShake128f,
        IavAlgorithmSlhDsaShake128s,
        IavAlgorithmSlhDsaShake192f,
        IavAlgorithmSlhDsaShake192s,
        IavAlgorithmSlhDsaShake256f,
        IavAlgorithmSlhDsaShake256s,
    };
    constexpr std::array<iav_algorithm, 6U> kKemAlgorithms = {IavAlgorithmMlKem512,
                                                              IavAlgorithmMlKem768,
                                                              IavAlgorithmMlKem1024,
                                                              IavAlgorithmHqc128,
                                                              IavAlgorithmHqc192,
                                                              IavAlgorithmHqc256};

    for (const iav_algorithm algorithm : kSignatureAlgorithms)
    {
        iav_primula_key_handle* output_key = nullptr;
        EXPECT_EQ(iav_kem_keypair_generate(algorithm, &output_key), IavStatusInvalidArgument);
        EXPECT_EQ(output_key, nullptr);
    }

    for (const iav_algorithm algorithm : kKemAlgorithms)
    {
        iav_primula_key_handle* output_key = nullptr;
        EXPECT_EQ(iav_keypair_generate(algorithm, &output_key), IavStatusInvalidArgument);
        EXPECT_EQ(output_key, nullptr);
    }

    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange): exercise an unrecognized ABI ID.
    constexpr auto kUnknownAlgorithm = static_cast<iav_algorithm>(30);
    iav_primula_key_handle* output_key = nullptr;
    EXPECT_EQ(iav_keypair_generate(kUnknownAlgorithm, &output_key), IavStatusUnsupportedAlgorithm);
    EXPECT_EQ(output_key, nullptr);
    EXPECT_EQ(iav_kem_keypair_generate(kUnknownAlgorithm, &output_key), IavStatusUnsupportedAlgorithm);
    EXPECT_EQ(output_key, nullptr);
}

}  // namespace
