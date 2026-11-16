// SPDX-License-Identifier: MIT

#include "test_helpers.h"

#include <stdio.h>

void OQS_print_hex_string(const char* label, const uint8_t* str, size_t len)
{
    printf("%-20s (%4zu bytes):  ", label, len);
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02X", str[i]);
    }
    printf("\n");
}

OQS_STATUS flip_bit(uint8_t* array, uint64_t array_length, uint64_t bit_position)
{
    const uint64_t byte_index = bit_position / 8U;
    const uint8_t bit_index = (uint8_t)(bit_position % 8U);
    if (byte_index >= array_length)
    {
        fprintf(stderr, "ERROR: flip_bit index is out of bounds!\n");
        return OQS_ERROR;
    }

    array[byte_index] ^= (uint8_t)(1U << bit_index);
    return OQS_SUCCESS;
}

OQS_STATUS test_sig_bitflip(OQS_SIG* sig,
                            uint8_t* message,
                            size_t message_len,
                            uint8_t* signature,
                            size_t signature_len,
                            uint8_t* public_key,
                            bool bitflips_all[2],
                            size_t bitflips[2],
                            bool use_ctx,
                            uint8_t* ctx,
                            size_t ctx_len)
{
    const int num_tests = sig->suf_cma ? 2 : 1;
    for (int test = 0; test < num_tests; ++test)
    {
        uint8_t* const tampered_array = (test == 1) ? signature : message;
        const size_t tampered_array_len = (test == 1) ? signature_len : message_len;
        const uint64_t bitflips_selected = bitflips_all[test] ? tampered_array_len * 8U : bitflips[test];
        for (uint64_t i = 0; i < bitflips_selected; ++i)
        {
            uint64_t random_bit_index = 0;
            OQS_randombytes((uint8_t*)&random_bit_index, sizeof(random_bit_index));
            OQS_TEST_CT_DECLASSIFY(&random_bit_index, sizeof(random_bit_index));
            random_bit_index %= (uint64_t)(tampered_array_len * 8U);
            const uint64_t bit_index = bitflips_all[test] ? i : random_bit_index;

            if (flip_bit(tampered_array, (uint64_t)tampered_array_len, bit_index) != OQS_SUCCESS)
            {
                return OQS_ERROR;
            }
            const OQS_STATUS verify_status =
                use_ctx ? OQS_SIG_verify_with_ctx_str(
                              sig, message, message_len, signature, signature_len, ctx, ctx_len, public_key)
                        : OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
            OQS_TEST_CT_DECLASSIFY(&verify_status, sizeof(verify_status));
            if (verify_status != OQS_ERROR)
            {
                fprintf(stderr,
                        "ERROR: OQS_SIG_verify should have failed after flipping bit %llu of the %s!\n",
                        (unsigned long long)bit_index,
                        (test == 0) ? "message" : "signature");
                (void)flip_bit(tampered_array, (uint64_t)tampered_array_len, bit_index);
                return OQS_ERROR;
            }
            if (flip_bit(tampered_array, (uint64_t)tampered_array_len, bit_index) != OQS_SUCCESS)
            {
                return OQS_ERROR;
            }
        }
    }
    return OQS_SUCCESS;
}
