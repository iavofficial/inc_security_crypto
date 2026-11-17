// SPDX-License-Identifier: MIT
#ifndef PQC_PROVIDER_LIBOQS_TEST_HELPERS_H
#define PQC_PROVIDER_LIBOQS_TEST_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_TEST_CONSTANT_TIME)
#include <valgrind/memcheck.h>
#define OQS_TEST_CT_CLASSIFY(addr, len) VALGRIND_MAKE_MEM_UNDEFINED((addr), (len))
#define OQS_TEST_CT_DECLASSIFY(addr, len) VALGRIND_MAKE_MEM_DEFINED((addr), (len))
#else
#define OQS_TEST_CT_CLASSIFY(addr, len)
#define OQS_TEST_CT_DECLASSIFY(addr, len)
#endif

void OQS_print_hex_string(const char* label, const uint8_t* str, size_t len);

OQS_STATUS flip_bit(uint8_t* array, uint64_t array_length, uint64_t bit_position);

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
                            size_t ctx_len);

#endif  // PQC_PROVIDER_LIBOQS_TEST_HELPERS_H
