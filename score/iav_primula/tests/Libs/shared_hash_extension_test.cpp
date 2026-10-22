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

/// @file shared_hash_extension_test.cpp
/// @brief Additional known-answer and incremental tests for SHA-2 and FIPS202.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

extern "C" {
#include "FsmSw_Fips202.h"
#include "FsmSw_sha2.h"
#include "score/iav_primula/include/Platform_Types.h"
}

namespace
{

std::vector<std::uint8_t> DecodeHex(std::string_view encoded)
{
    const auto nibble = [](char character) -> std::uint8_t {
        if (character >= '0' && character <= '9')
        {
            return static_cast<std::uint8_t>(character - '0');
        }
        if (character >= 'a' && character <= 'f')
        {
            return static_cast<std::uint8_t>(character - 'a' + 10);
        }
        return static_cast<std::uint8_t>(character - 'A' + 10);
    };

    std::vector<std::uint8_t> decoded;
    decoded.reserve(encoded.size() / 2U);
    for (std::size_t index = 0U; index + 1U < encoded.size(); index += 2U)
    {
        decoded.push_back(static_cast<std::uint8_t>((nibble(encoded[index]) << 4U) | nibble(encoded[index + 1U])));
    }
    return decoded;
}

template <typename ByteRange>
void ExpectBytesMatchHex(const ByteRange& actual, std::string_view expected_hex)
{
    const std::vector<std::uint8_t> expected = DecodeHex(expected_hex);
    ASSERT_EQ(actual.size(), expected.size());
    EXPECT_TRUE(std::equal(actual.begin(), actual.end(), expected.begin()));
}

template <typename Context,
          typename InitOperation,
          typename CloneOperation,
          typename BlocksOperation,
          typename FinalizeOperation,
          typename HashOperation,
          std::size_t DigestSize>
void CheckIncrementalPaddingCases(InitOperation init,
                                  CloneOperation clone,
                                  BlocksOperation blocks,
                                  FinalizeOperation finalize,
                                  HashOperation hash,
                                  std::size_t block_size,
                                  const std::array<std::size_t, 4U>& message_sizes,
                                  const std::array<std::string_view, 4U>& expected_hex)
{
    for (std::size_t test_index = 0U; test_index < message_sizes.size(); ++test_index)
    {
        const std::size_t message_size = message_sizes[test_index];
        std::vector<std::uint8_t> message(message_size);
        for (std::size_t index = 0U; index < message.size(); ++index)
        {
            message[index] = static_cast<std::uint8_t>(index);
        }

        std::array<std::uint8_t, DigestSize> one_shot{};
        std::array<std::uint8_t, DigestSize> incremental{};
        std::array<std::uint8_t, DigestSize> cloned_incremental{};
        hash(one_shot.data(), message.data(), static_cast<uint32>(message.size()));
        ExpectBytesMatchHex(one_shot, expected_hex[test_index]);

        const std::size_t complete_bytes = (message_size / block_size) * block_size;
        const uint32 complete_blocks = static_cast<uint32>(complete_bytes / block_size);
        const uint32 remainder = static_cast<uint32>(message_size - complete_bytes);
        Context state{};
        Context cloned_state{};
        init(&state);
        blocks(&state, message.data(), complete_blocks);
        clone(&cloned_state, &state);
        finalize(incremental.data(), &state, message.data() + complete_bytes, remainder);
        finalize(cloned_incremental.data(), &cloned_state, message.data() + complete_bytes, remainder);

        EXPECT_EQ(incremental, one_shot) << "message length=" << message_size;
        EXPECT_EQ(cloned_incremental, one_shot) << "message length=" << message_size;
    }
}

// M04 P1: SHA-224/384/512 were absent or lightly exercised after M02. These
// independent SHA-2 known-answer vectors establish correct digest output for
// each remaining variant; SHA-224 and SHA-384 expose no complete incremental
// init/finalize API, so their checks intentionally use the supported one-shot
// interface rather than reaching into private state.
TEST(Sha2ExtensionTest, Sha224Sha384AndSha512MatchIndependentKnownAnswers)
{
    static constexpr std::array<std::uint8_t, 3U> kMessage = {0x61U, 0x62U, 0x63U};
    std::array<std::uint8_t, 28U> sha224{};
    std::array<std::uint8_t, 48U> sha384{};
    std::array<std::uint8_t, 64U> sha512{};

    FsmSw_Sha224(sha224.data(), kMessage.data(), static_cast<uint32>(kMessage.size()));
    FsmSw_Sha384(sha384.data(), kMessage.data(), static_cast<uint32>(kMessage.size()));
    FsmSw_Sha512(sha512.data(), kMessage.data(), static_cast<uint32>(kMessage.size()));

    ExpectBytesMatchHex(sha224, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    ExpectBytesMatchHex(sha384,
                        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                        "8086072ba1e7cc2358baeca134c825a7");
    ExpectBytesMatchHex(sha512,
                        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

// M04 P1: exercise both sides of SHA-256's 56-byte and SHA-512-family's
// 112-byte final-block thresholds with independent vectors. The 119/120 and
// 239/240-byte inputs also force one complete input block before finalization;
// cloning at that point validates the public incremental continuation path.
TEST(Sha2ExtensionTest, IncrementalAndClonedStatesMatchPaddingBoundaryVectors)
{
    static constexpr std::array<std::size_t, 4U> kSha256Sizes = {55U, 56U, 119U, 120U};
    static constexpr std::array<std::string_view, 4U> kSha256Expected = {
        "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59",
        "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562",
        "da18797ed7c3a777f0847f429724a2d8cd5138e6ed2895c3fa1a6d39d18f7ec6",
        "f52b23db1fbb6ded89ef42a23ce0c8922c45f25c50b568a93bf1c075420bbb7c"};
    static constexpr std::array<std::size_t, 4U> kSha512Sizes = {111U, 112U, 239U, 240U};
    static constexpr std::array<std::string_view, 4U> kSha512Expected = {
        "a1a111449b198d9b1f538bad7f3fc1022b3a5b1a5e90a0bc860de8512746cbc31599e6c834de3a3235327af0b51ff57"
        "bf7acf1974a73014d9c3953812edc7c8d",
        "c5fbd731d19d2ae1180f001be72c2c1aaba1d7b094b3748880e24593b8e117a750e11c1bd867cc2f96dace8c8b74abd"
        "2d5c4f236be444e77d30d1916174070b9",
        "cb4c7fd522756d5781ad3a4f590a1d862906b960e7720136cb3fb36b563caa1ea5689134291fa79c80ccc2b4092b41"
        "df32ebdcb36dbe79db483440228c1622a8",
        "6c48466c9f6c07e4ab762c696b7eeb35cfe236fca73683e5fab873ac3489b4d2eb3d7afcce7e8165dbbf37aded3b5b"
        "0c889c0b7e0f1790a8330d8677429d91a5"};
    static constexpr std::array<std::string_view, 4U> kSha384Expected = {
        "f5f9fe110d809d34029de262a01b208356caec6e054c7f926b2591f6c9780579d4b59f5578c6f531a84f158a33660cef",
        "33ba080ec0ccb378e4e95fed3b26c23aa1a280476e007519ee47f60cd9c5c8a65d627259a9aa2fd33ca06d3c14ee5548",
        "2556cf077a788c49bb6d600f4a3cee635c4443832d169f761537afee2980742b9f34afbc87f598dd0aedc4a826ed6a73",
        "d64769ad58f5a338669b935f3431e5bef31667d0a2437bff78f1e5275075f434fff675f9833ea04ac4e5c2e2c2c99b8c"};

    // SHA-384 shares the SHA-512-family padding threshold but exposes only a
    // one-shot API, so validate these boundary cases against independent KATs.
    for (std::size_t test_index = 0U; test_index < kSha512Sizes.size(); ++test_index)
    {
        const std::size_t message_size = kSha512Sizes[test_index];
        std::vector<std::uint8_t> message(message_size);
        for (std::size_t index = 0U; index < message.size(); ++index)
        {
            message[index] = static_cast<std::uint8_t>(index);
        }
        std::array<std::uint8_t, 48U> digest{};
        FsmSw_Sha384(digest.data(), message.data(), static_cast<uint32>(message.size()));
        ExpectBytesMatchHex(digest, kSha384Expected[test_index]);
    }

    CheckIncrementalPaddingCases<sha256ctx,
                                 decltype(&FsmSw_Sha256_IncInit),
                                 decltype(&FsmSw_Sha256_IncCtxClone),
                                 decltype(&FsmSw_Sha256_IncBlocks),
                                 decltype(&FsmSw_Sha256_IncFinalize),
                                 decltype(&FsmSw_Sha256),
                                 32U>(FsmSw_Sha256_IncInit,
                                      FsmSw_Sha256_IncCtxClone,
                                      FsmSw_Sha256_IncBlocks,
                                      FsmSw_Sha256_IncFinalize,
                                      FsmSw_Sha256,
                                      64U,
                                      kSha256Sizes,
                                      kSha256Expected);
    CheckIncrementalPaddingCases<sha512ctx,
                                 decltype(&FsmSw_Sha512_IncInit),
                                 decltype(&FsmSw_Sha512_IncCtxClone),
                                 decltype(&FsmSw_Sha512_IncBlocks),
                                 decltype(&FsmSw_Sha512_IncFinalize),
                                 decltype(&FsmSw_Sha512),
                                 64U>(FsmSw_Sha512_IncInit,
                                      FsmSw_Sha512_IncCtxClone,
                                      FsmSw_Sha512_IncBlocks,
                                      FsmSw_Sha512_IncFinalize,
                                      FsmSw_Sha512,
                                      128U,
                                      kSha512Sizes,
                                      kSha512Expected);
}

// M04 P1: SHA3-384 and SHA3-512 have their own rates and were not covered by
// M02. Known answers anchor each variant; rate-minus-one plus two more absorbed
// bytes crosses each rate boundary, and cloned incremental contexts must agree
// with the one-shot result.
TEST(Fips202ExtensionTest, Sha3_384AndSha3_512MatchKnownAnswersAndCloneAcrossRates)
{
    static constexpr std::array<std::uint8_t, 1U> kEmpty = {0U};
    std::array<std::uint8_t, 48U> sha3_384_empty{};
    std::array<std::uint8_t, 64U> sha3_512_empty{};
    FsmSw_Fips202_Sha3_384(sha3_384_empty.data(), kEmpty.data(), 0U);
    FsmSw_Fips202_Sha3_512(sha3_512_empty.data(), kEmpty.data(), 0U);
    ExpectBytesMatchHex(sha3_384_empty,
                        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
                        "c3713831264adb47fb6bd1e058d5f004");
    ExpectBytesMatchHex(sha3_512_empty,
                        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                        "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");

    std::array<std::uint8_t, SHA3_384_RATE + 1U> message_384{};
    std::array<std::uint8_t, SHA3_512_RATE + 1U> message_512{};
    for (std::size_t index = 0U; index < message_384.size(); ++index)
    {
        message_384[index] = static_cast<std::uint8_t>(index);
    }
    for (std::size_t index = 0U; index < message_512.size(); ++index)
    {
        message_512[index] = static_cast<std::uint8_t>(index);
    }

    std::array<std::uint8_t, 48U> one_shot_384{};
    std::array<std::uint8_t, 48U> incremental_384{};
    std::array<std::uint8_t, 48U> cloned_384{};
    FsmSw_Fips202_Sha3_384(one_shot_384.data(), message_384.data(), static_cast<uint32>(message_384.size()));
    sha3_384incctx state_384{};
    sha3_384incctx clone_384{};
    FsmSw_Fips202_Sha3_384_IncInit(&state_384);
    FsmSw_Fips202_Sha3_384_IncAbsorb(&state_384, message_384.data(), SHA3_384_RATE - 1U);
    FsmSw_Fips202_Sha3_384_IncCtxClone(&clone_384, &state_384);
    FsmSw_Fips202_Sha3_384_IncAbsorb(&state_384, &message_384[SHA3_384_RATE - 1U], 2U);
    FsmSw_Fips202_Sha3_384_IncAbsorb(&clone_384, &message_384[SHA3_384_RATE - 1U], 2U);
    FsmSw_Fips202_Sha3_384_IncFinalize(incremental_384.data(), &state_384);
    FsmSw_Fips202_Sha3_384_IncFinalize(cloned_384.data(), &clone_384);
    EXPECT_EQ(incremental_384, one_shot_384);
    EXPECT_EQ(cloned_384, one_shot_384);

    std::array<std::uint8_t, 64U> one_shot_512{};
    std::array<std::uint8_t, 64U> incremental_512{};
    std::array<std::uint8_t, 64U> cloned_512{};
    FsmSw_Fips202_Sha3_512(one_shot_512.data(), message_512.data(), static_cast<uint32>(message_512.size()));
    sha3_512incctx state_512{};
    sha3_512incctx clone_512{};
    FsmSw_Fips202_Sha3_512_IncInit(&state_512);
    FsmSw_Fips202_Sha3_512_IncAbsorb(&state_512, message_512.data(), SHA3_512_RATE - 1U);
    FsmSw_Fips202_Sha3_512_IncCtxClone(&clone_512, &state_512);
    FsmSw_Fips202_Sha3_512_IncAbsorb(&state_512, &message_512[SHA3_512_RATE - 1U], 2U);
    FsmSw_Fips202_Sha3_512_IncAbsorb(&clone_512, &message_512[SHA3_512_RATE - 1U], 2U);
    FsmSw_Fips202_Sha3_512_IncFinalize(incremental_512.data(), &state_512);
    FsmSw_Fips202_Sha3_512_IncFinalize(cloned_512.data(), &clone_512);
    EXPECT_EQ(incremental_512, one_shot_512);
    EXPECT_EQ(cloned_512, one_shot_512);
}

// M04 P1: SHAKE256 was absent from the transferred primitive tests. Check its
// independent empty-input known answer, then compare one-shot output with cloned
// incremental squeezes below, at, above, and across multiple rate blocks. This
// targets both rate transitions and continuation after context cloning.
TEST(Fips202ExtensionTest, Shake256MatchesKnownAnswerAndSqueezesAcrossRateBoundaries)
{
    static constexpr std::array<std::uint8_t, 1U> kEmpty = {0U};
    static constexpr std::string_view kShake256Empty =
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
    std::array<std::uint8_t, 64U> known_answer{};
    FsmSw_Fips202_Shake256(known_answer.data(), static_cast<uint32>(known_answer.size()), kEmpty.data(), 0U);
    ExpectBytesMatchHex(known_answer, kShake256Empty);

    static constexpr std::array<std::size_t, 4U> kOutputSizes = {
        SHAKE256_RATE - 1U, SHAKE256_RATE, SHAKE256_RATE + 1U, (2U * SHAKE256_RATE) + 5U};
    for (const std::size_t output_size : kOutputSizes)
    {
        std::vector<std::uint8_t> one_shot(output_size);
        std::vector<std::uint8_t> incremental(output_size);
        std::vector<std::uint8_t> cloned_incremental(output_size);
        FsmSw_Fips202_Shake256(one_shot.data(), static_cast<uint32>(one_shot.size()), kEmpty.data(), 0U);

        shake256incctx state{};
        shake256incctx cloned_state{};
        FsmSw_Fips202_Shake256_IncInit(&state);
        FsmSw_Fips202_Shake256_IncAbsorb(&state, kEmpty.data(), 0U);
        FsmSw_Fips202_Shake256_IncFinalize(&state);
        FsmSw_Fips202_Shake256_IncCtxClone(&cloned_state, &state);
        FsmSw_Fips202_Shake256_IncSqueeze(incremental.data(), static_cast<uint32>(incremental.size()), &state);
        FsmSw_Fips202_Shake256_IncSqueeze(
            cloned_incremental.data(), static_cast<uint32>(cloned_incremental.size()), &cloned_state);

        EXPECT_EQ(incremental, one_shot) << "output length=" << output_size;
        EXPECT_EQ(cloned_incremental, one_shot) << "output length=" << output_size;
        if (output_size >= known_answer.size())
        {
            EXPECT_TRUE(std::equal(known_answer.begin(), known_answer.end(), one_shot.begin()));
        }
    }
}

// M04 P1: the transferred SHAKE128 test checked only a short prefix. Extend it
// across the SHAKE128 output rate, including one output spanning multiple rate
// blocks, and compare both incremental clones with the one-shot operation.
TEST(Fips202ExtensionTest, Shake128SqueezesAcrossRateBoundaries)
{
    static constexpr std::array<std::uint8_t, 1U> kEmpty = {0U};
    static constexpr std::array<std::size_t, 4U> kOutputSizes = {
        SHAKE128_RATE - 1U, SHAKE128_RATE, SHAKE128_RATE + 1U, (2U * SHAKE128_RATE) + 5U};
    for (const std::size_t output_size : kOutputSizes)
    {
        std::vector<std::uint8_t> one_shot(output_size);
        std::vector<std::uint8_t> incremental(output_size);
        std::vector<std::uint8_t> cloned_incremental(output_size);
        FsmSw_Fips202_Shake128(one_shot.data(), static_cast<uint32>(one_shot.size()), kEmpty.data(), 0U);

        shake128incctx state{};
        shake128incctx cloned_state{};
        FsmSw_Fips202_Shake128_IncInit(&state);
        FsmSw_Fips202_Shake128_IncAbsorb(&state, kEmpty.data(), 0U);
        FsmSw_Fips202_Shake128_IncFinalize(&state);
        FsmSw_Fips202_Shake128_IncCtxClone(&cloned_state, &state);
        FsmSw_Fips202_Shake128_IncSqueeze(incremental.data(), static_cast<uint32>(incremental.size()), &state);
        FsmSw_Fips202_Shake128_IncSqueeze(
            cloned_incremental.data(), static_cast<uint32>(cloned_incremental.size()), &cloned_state);

        EXPECT_EQ(incremental, one_shot) << "output length=" << output_size;
        EXPECT_EQ(cloned_incremental, one_shot) << "output length=" << output_size;
    }
}

}  // namespace
