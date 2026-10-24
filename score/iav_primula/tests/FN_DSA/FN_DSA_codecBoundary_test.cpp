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

/// @file FN_DSA_codecBoundary_test.cpp
/// @brief Boundary and malformed-input tests for the FN-DSA encodings.

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

extern "C" {
#include "FN_DSA_codec.h"
#include "score/iav_primula/include/Platform_Types.h"
}

namespace
{

constexpr uint32 kLogN = 1U;
constexpr std::size_t kCoefficientCount = 1U << kLogN;
constexpr uint32 kModqBitsPerCoefficient = 14U;
constexpr uint32 kTrimBits = 5U;
constexpr uint32 kCompMinimumBitsPerCoefficient = 9U;
constexpr uint32 kModqEncodedSize = static_cast<uint32>((kCoefficientCount * kModqBitsPerCoefficient + 7U) / 8U);
constexpr uint32 kTrimEncodedSize = static_cast<uint32>((kCoefficientCount * kTrimBits + 7U) / 8U);
constexpr std::size_t kCompZeroEncodedSize = (kCoefficientCount * kCompMinimumBitsPerCoefficient + 7U) / 8U;
constexpr uint32 kModqLimit = 12289U;
constexpr std::uint8_t kTestFill = 0xA5U;
constexpr std::uint8_t kNonzeroPaddingBit = 0x01U;
constexpr unsigned int kSignBitOffset = 7U;
constexpr std::uint8_t kNegativeZeroSignMask = static_cast<std::uint8_t>(1U << kSignBitOffset);
constexpr std::uint8_t kInvalidPackedByte = std::numeric_limits<std::uint8_t>::max();

// M04 P1 codec gap: the modq encoder supports NULL-output size queries and
// exact-capacity output. Round-trip valid boundary coefficients and present a
// one-byte-short logical capacity while retaining full physical backing; a
// sentinel checks that encoding stops at the caller-provided capacity.
TEST(FnDsaCodecBoundaryTest, ModqQueriesRoundTripsAndAcceptsExactCapacity)
{
    const std::array<std::uint16_t, kCoefficientCount> coefficients = {0U, static_cast<std::uint16_t>(kModqLimit - 1U)};
    EXPECT_EQ(kModqEncodedSize, FN_DSA_ModqEncode(nullptr, 0U, coefficients.data(), kLogN));

    std::array<std::uint8_t, kModqEncodedSize> encoded{};
    encoded.fill(kTestFill);
    EXPECT_EQ(0U, FN_DSA_ModqEncode(encoded.data(), kModqEncodedSize - 1U, coefficients.data(), kLogN));
    EXPECT_EQ(kTestFill, encoded.back());
    ASSERT_EQ(kModqEncodedSize, FN_DSA_ModqEncode(encoded.data(), kModqEncodedSize, coefficients.data(), kLogN));

    std::array<std::uint16_t, kCoefficientCount> decoded{};
    ASSERT_EQ(kModqEncodedSize, FN_DSA_ModqDecode(decoded.data(), kLogN, encoded.data(), kModqEncodedSize));
    EXPECT_EQ(coefficients, decoded);
}

// M04 P1 codec gap: modq must reject coefficients outside 0..12288 and
// malformed packed residues. Full-size arrays keep both rejected calls
// physically safe; these assertions check the documented zero return value.
TEST(FnDsaCodecBoundaryTest, ModqRejectsOutOfRangeCoefficientsAndResidues)
{
    const std::array<std::uint16_t, kCoefficientCount> invalid_coefficients = {static_cast<std::uint16_t>(kModqLimit),
                                                                               0U};
    std::array<std::uint8_t, kModqEncodedSize> encoded{};
    EXPECT_EQ(0U, FN_DSA_ModqEncode(encoded.data(), kModqEncodedSize, invalid_coefficients.data(), kLogN));

    std::array<std::uint16_t, kCoefficientCount> decoded{};
    // All-one packed input decodes an out-of-range 14-bit residue first.
    const std::array<std::uint8_t, kModqEncodedSize> invalid_residue = {
        kInvalidPackedByte, kInvalidPackedByte, kInvalidPackedByte, kInvalidPackedByte};
    EXPECT_EQ(0U, FN_DSA_ModqDecode(decoded.data(), kLogN, invalid_residue.data(), kModqEncodedSize));
}

// M04 P1 codec gap: the modq decoder must reject truncated data and nonzero
// unused low bits. The 28-bit sample leaves four padding bits; its mutated
// input keeps full physical capacity.
TEST(FnDsaCodecBoundaryTest, ModqRejectsTruncatedInputAndNonzeroPadding)
{
    const std::array<std::uint16_t, kCoefficientCount> coefficients = {0U, 1U};
    std::array<std::uint8_t, kModqEncodedSize> encoded{};
    ASSERT_EQ(kModqEncodedSize, FN_DSA_ModqEncode(encoded.data(), kModqEncodedSize, coefficients.data(), kLogN));

    std::array<std::uint16_t, kCoefficientCount> decoded{};
    EXPECT_EQ(0U, FN_DSA_ModqDecode(decoded.data(), kLogN, encoded.data(), kModqEncodedSize - 1U));

    std::array<std::uint8_t, kModqEncodedSize> nonzero_padding = encoded;
    nonzero_padding.back() |= kNonzeroPaddingBit;
    EXPECT_EQ(0U, FN_DSA_ModqDecode(decoded.data(), kLogN, nonzero_padding.data(), kModqEncodedSize));
}

// M04 P1 codec gap: trim encoding supports NULL-output size queries and
// exact-capacity output. Round-trip the valid extreme coefficients and present
// a one-byte-short logical capacity with full physical backing; the sentinel
// verifies that the logical capacity is respected.
TEST(FnDsaCodecBoundaryTest, TrimI8QueriesRoundTripsAndAcceptsExactCapacity)
{
    const std::array<std::int8_t, kCoefficientCount> coefficients = {-15, 15};
    EXPECT_EQ(kTrimEncodedSize, FN_DSA_TrimI8Encode(nullptr, 0U, coefficients.data(), kLogN, kTrimBits));

    std::array<std::uint8_t, kTrimEncodedSize> encoded{};
    encoded.fill(kTestFill);
    EXPECT_EQ(0U, FN_DSA_TrimI8Encode(encoded.data(), kTrimEncodedSize - 1U, coefficients.data(), kLogN, kTrimBits));
    EXPECT_EQ(kTestFill, encoded.back());
    ASSERT_EQ(kTrimEncodedSize,
              FN_DSA_TrimI8Encode(encoded.data(), kTrimEncodedSize, coefficients.data(), kLogN, kTrimBits));

    std::array<std::int8_t, kCoefficientCount> decoded{};
    ASSERT_EQ(kTrimEncodedSize,
              FN_DSA_TrimI8Decode(decoded.data(), kLogN, kTrimBits, encoded.data(), kTrimEncodedSize));
    EXPECT_EQ(coefficients, decoded);
}

// M04 P1 codec gap: trim must reject the forbidden -2^(bits-1) coefficient
// while encoding and decoding. The packed minimum is supplied directly to the
// decoder so that rejection is tested independently of encoder behavior.
TEST(FnDsaCodecBoundaryTest, TrimI8RejectsForbiddenMinimum)
{
    const std::array<std::int8_t, kCoefficientCount> invalid_coefficients = {-16, 0};
    std::array<std::uint8_t, kTrimEncodedSize> encoded{};
    EXPECT_EQ(0U, FN_DSA_TrimI8Encode(encoded.data(), kTrimEncodedSize, invalid_coefficients.data(), kLogN, kTrimBits));

    std::array<std::int8_t, kCoefficientCount> decoded{};
    // In five-bit two's-complement form this is -16 followed by zero.
    const std::array<std::uint8_t, kTrimEncodedSize> forbidden_minimum = {0x80U, 0x00U};
    EXPECT_EQ(0U, FN_DSA_TrimI8Decode(decoded.data(), kLogN, kTrimBits, forbidden_minimum.data(), kTrimEncodedSize));
}

// M04 P1 codec gap: trim decoding must reject truncated data and nonzero
// unused bits in the final byte. The valid pair uses ten bits in a two-byte
// allocation, leaving six low padding bits to mutate safely.
TEST(FnDsaCodecBoundaryTest, TrimI8RejectsTruncatedInputAndNonzeroPadding)
{
    const std::array<std::int8_t, kCoefficientCount> coefficients = {0, 1};
    std::array<std::uint8_t, kTrimEncodedSize> encoded{};
    ASSERT_EQ(kTrimEncodedSize,
              FN_DSA_TrimI8Encode(encoded.data(), kTrimEncodedSize, coefficients.data(), kLogN, kTrimBits));

    std::array<std::int8_t, kCoefficientCount> decoded{};
    EXPECT_EQ(0U, FN_DSA_TrimI8Decode(decoded.data(), kLogN, kTrimBits, encoded.data(), kTrimEncodedSize - 1U));

    std::array<std::uint8_t, kTrimEncodedSize> nonzero_padding = encoded;
    nonzero_padding.back() |= kNonzeroPaddingBit;
    EXPECT_EQ(0U, FN_DSA_TrimI8Decode(decoded.data(), kLogN, kTrimBits, nonzero_padding.data(), kTrimEncodedSize));
}

// M04 P1 codec gap: comp's variable-length format supports a NULL-output size
// query and exact-capacity round trip. A one-byte-short logical capacity is
// tested using the full queried size as physical backing.
TEST(FnDsaCodecBoundaryTest, CompQueriesRoundTripsAndAcceptsExactCapacity)
{
    const std::array<std::int16_t, kCoefficientCount> coefficients = {-2047, 2047};
    const uint32 required_size = FN_DSA_CompEncode(nullptr, 0U, coefficients.data(), kLogN);
    ASSERT_GT(required_size, 1U);

    std::vector<std::uint8_t> encoded(required_size, kTestFill);
    EXPECT_EQ(0U, FN_DSA_CompEncode(encoded.data(), required_size - 1U, coefficients.data(), kLogN));
    ASSERT_EQ(required_size, FN_DSA_CompEncode(encoded.data(), required_size, coefficients.data(), kLogN));

    std::array<std::int16_t, kCoefficientCount> decoded{};
    ASSERT_EQ(required_size, FN_DSA_CompDecode(decoded.data(), kLogN, encoded.data(), required_size));
    EXPECT_EQ(coefficients, decoded);
}

// M04 P1 codec gap: comp must reject coefficients outside the documented
// -2047..2047 range and insufficient logical output capacity. Full queried-size
// physical storage lets a sentinel check the final partial-byte boundary safely.
TEST(FnDsaCodecBoundaryTest, CompRejectsShortCapacityAndOutOfRangeCoefficients)
{
    const std::array<std::int16_t, kCoefficientCount> coefficients = {-2047, 2047};
    const uint32 required_size = FN_DSA_CompEncode(nullptr, 0U, coefficients.data(), kLogN);
    ASSERT_GT(required_size, 1U);

    std::vector<std::uint8_t> encoded(required_size, kTestFill);
    EXPECT_EQ(0U, FN_DSA_CompEncode(encoded.data(), required_size - 1U, coefficients.data(), kLogN));

    const std::array<std::int16_t, kCoefficientCount> zero_coefficients = {0, 0};
    const uint32 zero_encoded_size = FN_DSA_CompEncode(nullptr, 0U, zero_coefficients.data(), kLogN);
    ASSERT_EQ(kCompZeroEncodedSize, zero_encoded_size);
    std::array<std::uint8_t, kCompZeroEncodedSize> partial_byte_boundary{};
    partial_byte_boundary.fill(kTestFill);
    EXPECT_EQ(0U,
              FN_DSA_CompEncode(partial_byte_boundary.data(), zero_encoded_size - 1U, zero_coefficients.data(), kLogN));
    EXPECT_EQ(kTestFill, partial_byte_boundary.back());

    const std::array<std::int16_t, kCoefficientCount> invalid_coefficients = {-2048, 0};
    EXPECT_EQ(0U, FN_DSA_CompEncode(encoded.data(), required_size, invalid_coefficients.data(), kLogN));
}

// M04 P1 codec gap: comp decoding must reject truncated data, forbidden
// negative zero, and nonzero unused bits. Start with a valid two-zero encoding
// and mutate only a sign or padding bit while retaining full physical storage.
TEST(FnDsaCodecBoundaryTest, CompRejectsTruncatedAndMalformedZeroEncodings)
{
    const std::array<std::int16_t, kCoefficientCount> zero_coefficients = {0, 0};
    const uint32 zero_encoded_size = FN_DSA_CompEncode(nullptr, 0U, zero_coefficients.data(), kLogN);
    ASSERT_EQ(kCompZeroEncodedSize, zero_encoded_size);

    std::array<std::uint8_t, kCompZeroEncodedSize> encoded_zeros{};
    ASSERT_EQ(zero_encoded_size,
              FN_DSA_CompEncode(encoded_zeros.data(), zero_encoded_size, zero_coefficients.data(), kLogN));

    std::array<std::int16_t, kCoefficientCount> decoded{};
    EXPECT_EQ(0U, FN_DSA_CompDecode(decoded.data(), kLogN, encoded_zeros.data(), zero_encoded_size - 1U));

    std::array<std::uint8_t, kCompZeroEncodedSize> negative_zero = encoded_zeros;
    negative_zero[0U] |= kNegativeZeroSignMask;
    EXPECT_EQ(0U, FN_DSA_CompDecode(decoded.data(), kLogN, negative_zero.data(), zero_encoded_size));

    // Each zero coefficient occupies nine bits, leaving six low padding bits.
    std::array<std::uint8_t, kCompZeroEncodedSize> nonzero_padding = encoded_zeros;
    nonzero_padding.back() |= kNonzeroPaddingBit;
    EXPECT_EQ(0U, FN_DSA_CompDecode(decoded.data(), kLogN, nonzero_padding.data(), zero_encoded_size));
}

}  // namespace
