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

/**********************************************************************************************************************/
/* INCLUDES                                                                                                           */
/**********************************************************************************************************************/
#include <gtest/gtest.h>

extern "C" {
#include "FN_DSA_codec.h"
#include "FsmSw_CommonLib.h"
}

/**********************************************************************************************************************/
/* DEFINES                                                                                                            */
/**********************************************************************************************************************/
#define EXAMPLE_SIZE 1000
#define EXAMPLE_OUT_SIZE 64
#define EXAMPLE_IN_SIZE EXAMPLE_OUT_SIZE
#define FN_DSA_512_LOGN_VALUE 9

/**********************************************************************************************************************/
/* TEST CASES                                                                                                         */
/**********************************************************************************************************************/

/* FN_DSA_ModqEncode */
TEST(FN_DSA_512_codec_TEST, ModqEncodeElementOfXExceedsQ)
{
    uint32 max_out_len;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    max_out_len = n;
    uint16_t x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE] = {0};

    for (uint16_t i = 0; i < n; ++i)
    {
        x[i] = 13000;  // x[u] > 12289
    }

    int retVal = FN_DSA_ModqEncode(out, max_out_len, x, logn);
    EXPECT_EQ(retVal, 0);
}

/* FN_DSA_ModqEncode */
TEST(FN_DSA_512_codec_TEST, ModqEncodeOutEqNull)
{
    uint32 max_out_len, out_len;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    max_out_len = n;
    uint16_t x[n] = {0};

    out_len = ((((uint32)1 << logn) * 14) + 7) >> 3;  // function returns out_len
    int retVal = FN_DSA_ModqEncode(NULL, max_out_len, x, logn);
    EXPECT_EQ(retVal, out_len);
}

/* FN_DSA_ModqEncode */
TEST(FN_DSA_512_codec_TEST, ModqEncodeOutLenExceedsMaxOutLen)
{
    uint32 max_out_len = 0;  // ensure that out_len is greater than max_out_len
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    uint16_t x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE] = {0};

    int retVal = FN_DSA_ModqEncode(out, max_out_len, x, logn);
    EXPECT_EQ(retVal, 0);
}

/* FN_DSA_ModqEncode */
TEST(FN_DSA_512_codec_TEST, ModqEncodeIncompleteOutByte)
{
    uint32 max_out_len, out_len;
    const unsigned logn = 1;
    const unsigned n = (unsigned)1 << logn;
    uint16_t x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE] = {0};

    for (int i = 0; i < n; i++)
    {
        x[i] = 0x2fff;
    }
    uint8_t expected_out_len = 4;
    uint8_t last_element = expected_out_len - 1;
    uint8_t expected_last_element_val = 0xF0;

    int retVal = FN_DSA_ModqEncode(out, EXAMPLE_OUT_SIZE, x, logn);
    EXPECT_EQ(retVal, expected_out_len);
    EXPECT_EQ(out[last_element], expected_last_element_val);
}

/* FN_DSA_ModqDecode */
TEST(FN_DSA_512_codec_TEST, ModqDecodeInLenExceedsMaxInLen)
{
    uint32 max_in_len = 0;  // ensure in_len > max_in_len
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    uint16_t x[n] = {0};
    uint8_t in[EXAMPLE_IN_SIZE] = {0};

    int retVal = FN_DSA_ModqDecode(x, logn, in, max_in_len);
    EXPECT_EQ(retVal, 0);
}

/* FN_DSA_ModqDecode */
TEST(FN_DSA_512_codec_TEST, ModqDecodeWExceedsQ)
{
    uint32 max_in_len;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    max_in_len = (n * 14) >> 3;
    uint16_t x[n] = {0};
    uint8_t in[EXAMPLE_IN_SIZE] = {0};

    for (uint16_t i = 0; i < EXAMPLE_IN_SIZE; i++)
    {
        in[i] = 0xFF;
    }

    int retVal = FN_DSA_ModqDecode(x, logn, in, max_in_len);
    EXPECT_EQ(retVal, 0);
}

/* FN_DSA_TrimI8Encode */
TEST(FN_DSA_512_codec_TEST, TrimI16EncodeElementofXOutsideRange)
{
    uint32 max_out_len;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    max_out_len = n;
    unsigned bits = 8;
    sint8 x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE] = {0};

    for (uint16_t i = 0; i < n; i++)
    {
        x[i] = (1 << (bits - 1));  // ensure x[i] > maxv
    }

    int retVal = FN_DSA_TrimI8Encode(out, max_out_len, x, logn, bits);
    EXPECT_EQ(retVal, 0);
}

/* FN_DSA_TrimI8Encode */
TEST(FN_DSA_512_codec_TEST, TrimI16EncodeOutEqNULL)
{
    uint32 max_out_len, out_len;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    max_out_len = n;
    unsigned bits = 8;
    sint8 x[n] = {0};

    out_len = ((n * bits) + 7) >> 3;
    int retVal = FN_DSA_TrimI8Encode(NULL, max_out_len, x, logn, bits);
    EXPECT_EQ(retVal, out_len);
}

/* FN_DSA_TrimI8Encode */
TEST(FN_DSA_512_codec_TEST, TrimI16EncodeOutLenExceedsMaxOutLen)
{
    uint32 max_out_len = 0;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    unsigned bits = 8;
    sint8 x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE];
    (void)FsmSw_CommonLib_RandomBytes(out, EXAMPLE_OUT_SIZE);

    int retVal = FN_DSA_TrimI8Encode(out, max_out_len, x, logn, bits);
    EXPECT_EQ(retVal, 0);
}

/* FN_DSA_TrimI8Encode */
TEST(FN_DSA_512_codec_TEST, TrimI16EncodeIncompleteOutByte)
{
    const unsigned logn = 1;
    const unsigned n = (unsigned)1 << logn;
    unsigned bits = 8;
    sint8 x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE] = {0};

    for (uint8_t i = 0; i < n; i++)
    {
        x[i] = 0x7F;
    }

    uint8_t expected_out_len = ((n * bits) + 7) >> 3;  // 2, because logn = 1
    uint8_t last_element = expected_out_len - 1;
    uint8_t expected_last_element_val = 0x7F;

    int retVal = FN_DSA_TrimI8Encode(out, EXAMPLE_OUT_SIZE, x, logn, bits);
    EXPECT_EQ(retVal, expected_out_len);
    EXPECT_EQ(out[last_element], expected_last_element_val);
}

/* FN_DSA_TrimI8Encode */
TEST(FN_DSA_512_codec_TEST, TrimI16EncodeNothingWrong)
{
    uint32 max_out_len, out_len;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    max_out_len = n;
    unsigned bits = 8;
    sint8 x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE];
    (void)FsmSw_CommonLib_RandomBytes(out, EXAMPLE_OUT_SIZE);

    out_len = ((n * bits) + 7) >> 3;
    int retVal = FN_DSA_TrimI8Encode(out, max_out_len, x, logn, bits);
    EXPECT_EQ(retVal, out_len);
}

/* FN_DSA_TrimI8Decode */
TEST(FN_DSA_512_codec_TEST, TrimI16DecodeInLenExceedsMaxInLen)
{
    uint32 max_in_len = 0;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    unsigned bits = 8;
    sint8 x[n] = {0};
    uint8_t in[EXAMPLE_IN_SIZE] = {0};

    int retVal = FN_DSA_TrimI8Decode(x, logn, bits, in, max_in_len);
    EXPECT_EQ(retVal, 0);
}

/* FN_DSA_TrimI8Encode */
TEST(FN_DSA_512_codec_TEST, TrimI8EncodeElementofXOutsideRange)
{
    uint32 max_out_len;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    max_out_len = n;
    unsigned bits = 1;  // maxv = 0, ensure x[u] > maxv
    sint8 x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE] = {0};

    for (uint16_t i = 0; i < n; i++)
    {
        x[i] = (1 << (bits - 1));  // ensure x[i] > maxv
    }

    int retVal = FN_DSA_TrimI8Encode(out, max_out_len, x, logn, bits);
    EXPECT_EQ(retVal, 0);
}

/* FN_DSA_TrimI8Encode */
TEST(FN_DSA_512_codec_TEST, TrimI8EncodeOutEqNULL)
{
    uint32 max_out_len, out_len;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    max_out_len = n;
    unsigned bits = 8;
    sint8 x[n] = {0};

    out_len = ((n * bits) + 7) >> 3;
    int retVal = FN_DSA_TrimI8Encode(NULL, max_out_len, x, logn, bits);
    EXPECT_EQ(retVal, out_len);
}

/* FN_DSA_TrimI8Encode */
TEST(FN_DSA_512_codec_TEST, TrimI8EncodeOutLenExceedsMaxOutLen)
{
    uint32 max_out_len = 0;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    unsigned bits = 8;
    sint8 x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE];
    (void)FsmSw_CommonLib_RandomBytes(out, EXAMPLE_OUT_SIZE);

    int retVal = FN_DSA_TrimI8Encode(out, max_out_len, x, logn, bits);
    EXPECT_EQ(retVal, 0);
}

/* FN_DSA_TrimI8Encode */
TEST(FN_DSA_512_codec_TEST, TrimI8EncodeIncompleteOutByte)
{
    const unsigned logn = 1;
    const unsigned n = (unsigned)1 << logn;
    unsigned bits = 8;
    sint8 x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE] = {0};

    for (uint8_t i = 0; i < n; i++)
    {
        x[i] = 0x7F;
    }

    uint8_t expected_out_len = ((n * bits) + 7) >> 3;  // 2, because logn = 1
    uint8_t last_element = expected_out_len - 1;
    uint8_t expected_last_element_val = 0x7F;

    int retVal = FN_DSA_TrimI8Encode(out, EXAMPLE_OUT_SIZE, x, logn, bits);
    EXPECT_EQ(retVal, expected_out_len);
    EXPECT_EQ(out[last_element], expected_last_element_val);
}

/* FN_DSA_TrimI8Encode */
TEST(FN_DSA_512_codec_TEST, TrimI8EncodeNothingWrong)
{
    uint32 max_out_len, out_len;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    unsigned bits = 8;
    max_out_len = n;
    sint8 x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE];
    (void)FsmSw_CommonLib_RandomBytes(out, EXAMPLE_OUT_SIZE);

    out_len = ((n * bits) + 7) >> 3;
    int retVal = FN_DSA_TrimI8Encode(out, max_out_len, x, logn, bits);
    EXPECT_EQ(retVal, out_len);
}

/* FN_DSA_TrimI8Decode */
TEST(FN_DSA_512_codec_TEST, TrimI8DecodeInLenExceedsMaxInLen)
{
    uint32 max_in_len = 0;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    unsigned bits = 8;
    sint8 x[n] = {0};
    uint8_t in[EXAMPLE_IN_SIZE] = {0};

    int retVal = FN_DSA_TrimI8Decode(x, logn, bits, in, max_in_len);
    EXPECT_EQ(retVal, 0);
}

/* FN_DSA_CompEncode */
TEST(FN_DSA_512_codec_TEST, CompEncodeElementOfXOutsideRange)
{
    uint32 max_out_len;
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    max_out_len = n;
    sint16 x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE] = {0};

    for (uint16_t i = 0; i < n; ++i)
    {
        x[i] = 2100;  // ensure x[i] > 2047, so is outside the range
    }

    int retVal = FN_DSA_CompEncode(out, max_out_len, x, logn);
    EXPECT_EQ(retVal, 0);
}

/* FN_DSA_CompEncode */
TEST(FN_DSA_512_codec_TEST, CompEncodeVExceedsMaxOutLen)
{
    uint32 max_out_len = 0;  // ensure v > max_out_len
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    sint16 x[n] = {0};
    uint8_t out[EXAMPLE_OUT_SIZE];
    (void)FsmSw_CommonLib_RandomBytes(out, EXAMPLE_OUT_SIZE);

    int retVal = FN_DSA_CompEncode(out, max_out_len, x, logn);
    EXPECT_EQ(retVal, 0);
}

/* FN_DSA_CompDecode */
TEST(FN_DSA_512_codec_TEST, CompDecodeVExceedsManInLen)
{
    uint32 max_in_len = 0;  // ensure v > max_in_len
    const unsigned logn = FN_DSA_512_LOGN_VALUE;
    const unsigned n = (unsigned)1 << logn;
    sint16 x[n] = {0};
    uint8_t in[EXAMPLE_IN_SIZE] = {0};

    int retVal = FN_DSA_CompDecode(x, logn, in, max_in_len);
    EXPECT_EQ(retVal, 0);
}
