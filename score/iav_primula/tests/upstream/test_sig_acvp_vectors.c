// SPDX-License-Identifier: MIT

#include <oqs/oqs.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ACVP_CASE_COUNT 615
#define MAX_VECTOR_LINE (1024 * 1024)
#define MLDSA_RANDOM_BYTES 32
#define ANY_LENGTH ((size_t) - 1)
#define MAX_FIELDS 12

typedef int (*ml_dsa_sign_fn)(uint8_t* signature,
                              size_t* signature_length,
                              const uint8_t* message,
                              size_t message_length,
                              const uint8_t* prefix_or_context,
                              size_t prefix_or_context_length,
                              const uint8_t* randomness,
                              const uint8_t* secret_key,
                              int mode);

typedef int (*ml_dsa_verify_fn)(const uint8_t* signature,
                                size_t signature_length,
                                const uint8_t* message,
                                size_t message_length,
                                const uint8_t* prefix_or_context,
                                size_t prefix_or_context_length,
                                const uint8_t* public_key,
                                int mode);

#define DECLARE_MLDSA_INTERNALS(parameter)                                                                       \
    extern int PQCP_MLDSA_NATIVE_MLDSA##parameter##_C_signature_internal(                                        \
        uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, const uint8_t*, int); \
    extern int PQCP_MLDSA_NATIVE_MLDSA##parameter##_C_signature_pre_hash_internal(                               \
        uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, const uint8_t*, int); \
    extern int PQCP_MLDSA_NATIVE_MLDSA##parameter##_C_verify_internal(                                           \
        const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, int);            \
    extern int PQCP_MLDSA_NATIVE_MLDSA##parameter##_C_verify_pre_hash_internal(                                  \
        const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, int)

DECLARE_MLDSA_INTERNALS(44);
DECLARE_MLDSA_INTERNALS(65);
DECLARE_MLDSA_INTERNALS(87);

typedef struct
{
    const char* name;
    ml_dsa_sign_fn sign_internal;
    ml_dsa_sign_fn sign_pre_hash;
    ml_dsa_verify_fn verify_internal;
    ml_dsa_verify_fn verify_pre_hash;
    size_t expected_cases[7];
} parameter_set_t;

static const parameter_set_t parameter_sets[] = {
    {"ML-DSA-44",
     PQCP_MLDSA_NATIVE_MLDSA44_C_signature_internal,
     PQCP_MLDSA_NATIVE_MLDSA44_C_signature_pre_hash_internal,
     PQCP_MLDSA_NATIVE_MLDSA44_C_verify_internal,
     PQCP_MLDSA_NATIVE_MLDSA44_C_verify_pre_hash_internal,
     {25, 60, 30, 30, 30, 15, 15}},
    {"ML-DSA-65",
     PQCP_MLDSA_NATIVE_MLDSA65_C_signature_internal,
     PQCP_MLDSA_NATIVE_MLDSA65_C_signature_pre_hash_internal,
     PQCP_MLDSA_NATIVE_MLDSA65_C_verify_internal,
     PQCP_MLDSA_NATIVE_MLDSA65_C_verify_pre_hash_internal,
     {25, 60, 30, 30, 30, 15, 15}},
    {"ML-DSA-87",
     PQCP_MLDSA_NATIVE_MLDSA87_C_signature_internal,
     PQCP_MLDSA_NATIVE_MLDSA87_C_signature_pre_hash_internal,
     PQCP_MLDSA_NATIVE_MLDSA87_C_verify_internal,
     PQCP_MLDSA_NATIVE_MLDSA87_C_verify_pre_hash_internal,
     {25, 60, 30, 30, 30, 15, 15}},
};

typedef enum
{
    CASE_KEYGEN = 0,
    CASE_SIGGEN_INTERNAL,
    CASE_SIGGEN_EXTERNAL,
    CASE_SIGGEN_PREHASH,
    CASE_SIGVER_INTERNAL,
    CASE_SIGVER_EXTERNAL,
    CASE_SIGVER_PREHASH,
    CASE_KIND_COUNT,
} case_kind_t;

static const char* const case_names[CASE_KIND_COUNT] = {
    "keygen",
    "siggen_internal",
    "siggen_external",
    "siggen_prehash",
    "sigver_internal",
    "sigver_external",
    "sigver_prehash",
};

static const uint8_t* random_input;
static size_t random_input_length;
static size_t random_input_offset;
static bool random_input_overread;

static void fixed_randombytes(uint8_t* output, size_t length)
{
    size_t available = random_input_length - random_input_offset;
    size_t copied = length < available ? length : available;
    if (copied != 0)
    {
        memcpy(output, random_input + random_input_offset, copied);
    }
    if (copied < length)
    {
        memset(output + copied, 0, length - copied);
        random_input_overread = true;
    }
    random_input_offset += copied;
}

static void set_fixed_randombytes(const uint8_t* input, size_t length)
{
    random_input = input;
    random_input_length = length;
    random_input_offset = 0;
    random_input_overread = false;
    OQS_randombytes_custom_algorithm(fixed_randombytes);
}

static bool reset_randombytes(void)
{
    bool bytes_consumed_exactly = !random_input_overread && random_input_offset == random_input_length;
    bool reset_succeeded = OQS_randombytes_switch_algorithm("system") == OQS_SUCCESS;
    random_input = NULL;
    random_input_length = 0;
    random_input_offset = 0;
    random_input_overread = false;
    return bytes_consumed_exactly && reset_succeeded;
}

static bool parse_case_kind(const char* text, case_kind_t* kind)
{
    for (size_t i = 0; i < CASE_KIND_COUNT; ++i)
    {
        if (strcmp(text, case_names[i]) == 0)
        {
            *kind = (case_kind_t)i;
            return true;
        }
    }
    return false;
}

static const parameter_set_t* find_parameter_set(const char* name, size_t* index)
{
    for (size_t i = 0; i < sizeof(parameter_sets) / sizeof(parameter_sets[0]); ++i)
    {
        if (strcmp(name, parameter_sets[i].name) == 0)
        {
            *index = i;
            return &parameter_sets[i];
        }
    }
    return NULL;
}

static bool parse_positive_u32(const char* text, uint32_t* value)
{
    char* end = NULL;
    unsigned long parsed = strtoul(text, &end, 10);
    if (text[0] == '\0' || *end != '\0' || parsed == 0 || parsed > UINT32_MAX)
    {
        return false;
    }
    *value = (uint32_t)parsed;
    return true;
}

static bool parse_boolean(const char* text, bool* value)
{
    if (strcmp(text, "0") == 0)
    {
        *value = false;
        return true;
    }
    if (strcmp(text, "1") == 0)
    {
        *value = true;
        return true;
    }
    return false;
}

static bool split_fields(char* line, char** fields, size_t capacity, size_t* count)
{
    *count = 0;
    fields[(*count)++] = line;
    for (char* cursor = line; *cursor != '\0'; ++cursor)
    {
        if (*cursor == '\t')
        {
            *cursor = '\0';
            if (*count == capacity)
            {
                return false;
            }
            fields[(*count)++] = cursor + 1;
        }
    }
    return true;
}

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9')
    {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f')
    {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F')
    {
        return value - 'A' + 10;
    }
    return -1;
}

static bool decode_hex_field(const char* text, size_t expected_length, uint8_t** output, size_t* output_length)
{
    size_t text_length = strlen(text);
    *output = NULL;
    *output_length = 0;
    if ((text_length % 2) != 0)
    {
        return false;
    }
    size_t byte_length = text_length / 2;
    if (expected_length != ANY_LENGTH && byte_length != expected_length)
    {
        return false;
    }
    if (byte_length == 0)
    {
        return true;
    }
    uint8_t* decoded = OQS_MEM_malloc(byte_length);
    if (decoded == NULL)
    {
        return false;
    }
    for (size_t i = 0; i < byte_length; ++i)
    {
        int high = hex_nibble(text[2 * i]);
        int low = hex_nibble(text[2 * i + 1]);
        if (high < 0 || low < 0)
        {
            OQS_MEM_insecure_free(decoded);
            return false;
        }
        decoded[i] = (uint8_t)((high << 4) | low);
    }
    *output = decoded;
    *output_length = byte_length;
    return true;
}

static void free_buffer(uint8_t* buffer, size_t length, bool secret)
{
    if (buffer == NULL)
    {
        return;
    }
    if (secret)
    {
        OQS_MEM_secure_free(buffer, length);
    }
    else
    {
        OQS_MEM_insecure_free(buffer);
    }
}

static bool report_case_failure(const char* operation,
                                const parameter_set_t* parameter_set,
                                uint32_t group_id,
                                uint32_t tc_id,
                                const char* reason)
{
    fprintf(stderr, "ACVP %s %s tgId=%u tcId=%u: %s\n", operation, parameter_set->name, group_id, tc_id, reason);
    return false;
}

static bool run_case(case_kind_t kind,
                     const parameter_set_t* parameter_set,
                     char* const* values,
                     uint32_t group_id,
                     uint32_t tc_id)
{
    bool passed = false;
    bool expected_pass = false;
    bool external_mu = false;
    OQS_SIG* sig = OQS_SIG_new(parameter_set->name);
    uint8_t *message = NULL, *context = NULL, *randomness = NULL;
    uint8_t *public_key = NULL, *secret_key = NULL, *expected_signature = NULL;
    uint8_t *actual_public_key = NULL, *actual_secret_key = NULL, *actual_signature = NULL;
    size_t message_length = 0, context_length = 0, randomness_length = 0;
    size_t public_key_length = 0, secret_key_length = 0, expected_signature_length = 0;
    size_t actual_signature_length = 0;
    bool random_source_installed = false;
    int operation_status = -1;
    uint32_t hash_algorithm = 0;
    const uint8_t empty_message = 0;
    const uint8_t* message_bytes = &empty_message;
    const uint8_t* context_bytes = NULL;

    if (sig == NULL)
    {
        return report_case_failure(case_names[kind], parameter_set, group_id, tc_id, "algorithm is not enabled");
    }

    if (kind == CASE_KEYGEN)
    {
        if (!decode_hex_field(values[0], MLDSA_RANDOM_BYTES, &randomness, &randomness_length) ||
            !decode_hex_field(values[1], sig->length_public_key, &public_key, &public_key_length) ||
            !decode_hex_field(values[2], sig->length_secret_key, &secret_key, &secret_key_length))
        {
            report_case_failure(
                case_names[kind], parameter_set, group_id, tc_id, "malformed vector or allocation failure");
            goto cleanup;
        }
        actual_public_key = OQS_MEM_malloc(sig->length_public_key);
        actual_secret_key = OQS_MEM_malloc(sig->length_secret_key);
        if (actual_public_key == NULL || actual_secret_key == NULL)
        {
            report_case_failure(case_names[kind], parameter_set, group_id, tc_id, "allocation failure");
            goto cleanup;
        }
        set_fixed_randombytes(randomness, randomness_length);
        random_source_installed = true;
        operation_status = OQS_SIG_keypair(sig, actual_public_key, actual_secret_key);
        bool rng_ok = reset_randombytes();
        random_source_installed = false;
        passed = operation_status == OQS_SUCCESS && rng_ok &&
                 memcmp(actual_public_key, public_key, sig->length_public_key) == 0 &&
                 memcmp(actual_secret_key, secret_key, sig->length_secret_key) == 0;
        if (!passed)
        {
            report_case_failure(
                case_names[kind], parameter_set, group_id, tc_id, "key pair mismatch or operation failure");
        }
        goto cleanup;
    }

    switch (kind)
    {
        case CASE_SIGGEN_INTERNAL:
            if (!decode_hex_field(values[0], ANY_LENGTH, &message, &message_length) ||
                !decode_hex_field(values[1], MLDSA_RANDOM_BYTES, &randomness, &randomness_length) ||
                !decode_hex_field(values[2], sig->length_secret_key, &secret_key, &secret_key_length) ||
                !decode_hex_field(values[3], sig->length_signature, &expected_signature, &expected_signature_length) ||
                !parse_boolean(values[4], &external_mu))
            {
                report_case_failure(
                    case_names[kind], parameter_set, group_id, tc_id, "malformed vector or allocation failure");
                goto cleanup;
            }
            message_bytes = message != NULL ? message : &empty_message;
            actual_signature = OQS_MEM_malloc(sig->length_signature);
            if (actual_signature == NULL)
            {
                report_case_failure(case_names[kind], parameter_set, group_id, tc_id, "allocation failure");
                goto cleanup;
            }
            actual_signature_length = sig->length_signature;
            operation_status = parameter_set->sign_internal(actual_signature,
                                                            &actual_signature_length,
                                                            message_bytes,
                                                            message_length,
                                                            NULL,
                                                            0,
                                                            randomness,
                                                            secret_key,
                                                            external_mu ? 1 : 0);
            passed = operation_status == 0 && actual_signature_length == expected_signature_length &&
                     memcmp(actual_signature, expected_signature, expected_signature_length) == 0;
            break;

        case CASE_SIGGEN_EXTERNAL:
            if (!decode_hex_field(values[0], ANY_LENGTH, &message, &message_length) ||
                !decode_hex_field(values[1], ANY_LENGTH, &context, &context_length) ||
                !decode_hex_field(values[2], MLDSA_RANDOM_BYTES, &randomness, &randomness_length) ||
                !decode_hex_field(values[3], sig->length_secret_key, &secret_key, &secret_key_length) ||
                !decode_hex_field(values[4], sig->length_signature, &expected_signature, &expected_signature_length))
            {
                report_case_failure(
                    case_names[kind], parameter_set, group_id, tc_id, "malformed vector or allocation failure");
                goto cleanup;
            }
            message_bytes = message != NULL ? message : &empty_message;
            context_bytes = context_length != 0 ? context : NULL;
            actual_signature = OQS_MEM_malloc(sig->length_signature);
            if (actual_signature == NULL)
            {
                report_case_failure(case_names[kind], parameter_set, group_id, tc_id, "allocation failure");
                goto cleanup;
            }
            actual_signature_length = sig->length_signature;
            set_fixed_randombytes(randomness, randomness_length);
            random_source_installed = true;
            operation_status = OQS_SIG_sign_with_ctx_str(sig,
                                                         actual_signature,
                                                         &actual_signature_length,
                                                         message_bytes,
                                                         message_length,
                                                         context_bytes,
                                                         context_length,
                                                         secret_key);
            {
                bool rng_ok = reset_randombytes();
                random_source_installed = false;
                passed = operation_status == OQS_SUCCESS && rng_ok &&
                         actual_signature_length == expected_signature_length &&
                         memcmp(actual_signature, expected_signature, expected_signature_length) == 0;
            }
            break;

        case CASE_SIGGEN_PREHASH:
            if (!decode_hex_field(values[0], ANY_LENGTH, &message, &message_length) ||
                !decode_hex_field(values[1], ANY_LENGTH, &context, &context_length) ||
                !decode_hex_field(values[2], MLDSA_RANDOM_BYTES, &randomness, &randomness_length) ||
                !decode_hex_field(values[3], sig->length_secret_key, &secret_key, &secret_key_length) ||
                !decode_hex_field(values[4], sig->length_signature, &expected_signature, &expected_signature_length) ||
                !parse_positive_u32(values[5], &hash_algorithm) || hash_algorithm > 12)
            {
                report_case_failure(case_names[kind],
                                    parameter_set,
                                    group_id,
                                    tc_id,
                                    "malformed pre-hash vector or allocation failure");
                goto cleanup;
            }
            message_bytes = message != NULL ? message : &empty_message;
            context_bytes = context_length != 0 ? context : NULL;
            actual_signature = OQS_MEM_malloc(sig->length_signature);
            if (actual_signature == NULL)
            {
                report_case_failure(case_names[kind], parameter_set, group_id, tc_id, "allocation failure");
                goto cleanup;
            }
            actual_signature_length = sig->length_signature;
            operation_status = parameter_set->sign_pre_hash(actual_signature,
                                                            &actual_signature_length,
                                                            message_bytes,
                                                            message_length,
                                                            context_bytes,
                                                            context_length,
                                                            randomness,
                                                            secret_key,
                                                            (int)hash_algorithm);
            passed = operation_status == 0 && actual_signature_length == expected_signature_length &&
                     memcmp(actual_signature, expected_signature, expected_signature_length) == 0;
            break;

        case CASE_SIGVER_INTERNAL:
            if (!decode_hex_field(values[0], sig->length_public_key, &public_key, &public_key_length) ||
                !decode_hex_field(values[1], ANY_LENGTH, &message, &message_length) ||
                !decode_hex_field(values[2], sig->length_signature, &expected_signature, &expected_signature_length) ||
                !parse_boolean(values[3], &expected_pass) || !parse_boolean(values[4], &external_mu))
            {
                report_case_failure(
                    case_names[kind], parameter_set, group_id, tc_id, "malformed vector or allocation failure");
                goto cleanup;
            }
            message_bytes = message != NULL ? message : &empty_message;
            operation_status = parameter_set->verify_internal(expected_signature,
                                                              expected_signature_length,
                                                              message_bytes,
                                                              message_length,
                                                              NULL,
                                                              0,
                                                              public_key,
                                                              external_mu ? 1 : 0);
            passed = (operation_status == 0) == expected_pass;
            break;

        case CASE_SIGVER_EXTERNAL:
            if (!decode_hex_field(values[0], sig->length_public_key, &public_key, &public_key_length) ||
                !decode_hex_field(values[1], ANY_LENGTH, &message, &message_length) ||
                !decode_hex_field(values[2], sig->length_signature, &expected_signature, &expected_signature_length) ||
                !decode_hex_field(values[3], ANY_LENGTH, &context, &context_length) ||
                !parse_boolean(values[4], &expected_pass))
            {
                report_case_failure(
                    case_names[kind], parameter_set, group_id, tc_id, "malformed vector or allocation failure");
                goto cleanup;
            }
            message_bytes = message != NULL ? message : &empty_message;
            context_bytes = context_length != 0 ? context : NULL;
            operation_status = OQS_SIG_verify_with_ctx_str(sig,
                                                           message_bytes,
                                                           message_length,
                                                           expected_signature,
                                                           expected_signature_length,
                                                           context_bytes,
                                                           context_length,
                                                           public_key);
            passed = (operation_status == OQS_SUCCESS) == expected_pass;
            break;

        case CASE_SIGVER_PREHASH:
            if (!decode_hex_field(values[0], sig->length_public_key, &public_key, &public_key_length) ||
                !decode_hex_field(values[1], ANY_LENGTH, &message, &message_length) ||
                !decode_hex_field(values[2], sig->length_signature, &expected_signature, &expected_signature_length) ||
                !decode_hex_field(values[3], ANY_LENGTH, &context, &context_length) ||
                !parse_boolean(values[4], &expected_pass) || !parse_positive_u32(values[5], &hash_algorithm) ||
                hash_algorithm > 12)
            {
                report_case_failure(case_names[kind],
                                    parameter_set,
                                    group_id,
                                    tc_id,
                                    "malformed pre-hash vector or allocation failure");
                goto cleanup;
            }
            message_bytes = message != NULL ? message : &empty_message;
            context_bytes = context_length != 0 ? context : NULL;
            operation_status = parameter_set->verify_pre_hash(expected_signature,
                                                              expected_signature_length,
                                                              message_bytes,
                                                              message_length,
                                                              context_bytes,
                                                              context_length,
                                                              public_key,
                                                              (int)hash_algorithm);
            passed = (operation_status == 0) == expected_pass;
            break;

        case CASE_KEYGEN:
        case CASE_KIND_COUNT:
            break;
    }

    if (!passed)
    {
        report_case_failure(
            case_names[kind], parameter_set, group_id, tc_id, "operation result does not match ACVP vector");
    }

cleanup:
    if (random_source_installed)
    {
        (void)reset_randombytes();
    }
    free_buffer(message, message_length, false);
    free_buffer(context, context_length, false);
    free_buffer(randomness, randomness_length, true);
    free_buffer(public_key, public_key_length, false);
    free_buffer(secret_key, secret_key_length, true);
    free_buffer(expected_signature, expected_signature_length, false);
    free_buffer(actual_public_key, sig->length_public_key, false);
    free_buffer(actual_secret_key, sig->length_secret_key, true);
    free_buffer(actual_signature, sig->length_signature, false);
    OQS_SIG_free(sig);
    return passed;
}

static size_t expected_field_count(case_kind_t kind)
{
    static const size_t counts[CASE_KIND_COUNT] = {7, 9, 9, 10, 9, 9, 10};
    return counts[kind];
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: test_sig_acvp_vectors VECTOR_TSV\n");
        return EXIT_FAILURE;
    }

    FILE* vectors = fopen(argv[1], "r");
    if (vectors == NULL)
    {
        fprintf(stderr, "cannot open vendored ACVP vector data: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    size_t case_counts[sizeof(parameter_sets) / sizeof(parameter_sets[0])][CASE_KIND_COUNT] = {{0}};
    char line[MAX_VECTOR_LINE];
    size_t total_cases = 0;
    bool ok = true;
    OQS_init();

    while (fgets(line, sizeof(line), vectors) != NULL)
    {
        size_t line_length = strlen(line);
        if (line_length == 0 || (line[line_length - 1] != '\n' && !feof(vectors)))
        {
            fprintf(stderr, "ACVP vector line is empty or exceeds %d bytes\n", MAX_VECTOR_LINE - 1);
            ok = false;
            break;
        }
        if (line[line_length - 1] == '\n')
        {
            line[--line_length] = '\0';
        }
        if (line_length != 0 && line[line_length - 1] == '\r')
        {
            line[--line_length] = '\0';
        }
        if (line_length == 0)
        {
            fprintf(stderr, "empty ACVP vector row at line %zu\n", total_cases + 1);
            ok = false;
            break;
        }

        char* fields[MAX_FIELDS];
        size_t field_count = 0;
        if (!split_fields(line, fields, MAX_FIELDS, &field_count) || field_count < 4)
        {
            fprintf(stderr, "malformed ACVP TSV row at line %zu\n", total_cases + 1);
            ok = false;
            break;
        }

        case_kind_t kind;
        size_t parameter_index = 0;
        uint32_t group_id = 0, tc_id = 0;
        const parameter_set_t* parameter_set = NULL;
        if (!parse_case_kind(fields[0], &kind) ||
            (parameter_set = find_parameter_set(fields[1], &parameter_index)) == NULL ||
            !parse_positive_u32(fields[2], &group_id) || !parse_positive_u32(fields[3], &tc_id))
        {
            fprintf(stderr, "invalid ACVP row identity at line %zu\n", total_cases + 1);
            ok = false;
            break;
        }
        if (field_count != expected_field_count(kind))
        {
            fprintf(stderr,
                    "ACVP %s %s tgId=%u tcId=%u: expected %zu TSV columns, got %zu\n",
                    case_names[kind],
                    parameter_set->name,
                    group_id,
                    tc_id,
                    expected_field_count(kind),
                    field_count);
            ok = false;
            break;
        }
        if (!run_case(kind, parameter_set, &fields[4], group_id, tc_id))
        {
            ok = false;
            break;
        }
        ++case_counts[parameter_index][kind];
        ++total_cases;
    }

    if (ferror(vectors))
    {
        perror("reading ACVP vectors");
        ok = false;
    }
    if (fclose(vectors) != 0)
    {
        perror("closing ACVP vectors");
        ok = false;
    }

    for (size_t parameter_index = 0; parameter_index < sizeof(parameter_sets) / sizeof(parameter_sets[0]);
         ++parameter_index)
    {
        for (size_t kind = 0; kind < CASE_KIND_COUNT; ++kind)
        {
            if (case_counts[parameter_index][kind] != parameter_sets[parameter_index].expected_cases[kind])
            {
                fprintf(stderr,
                        "ACVP %s %s: expected %zu cases, ran %zu\n",
                        case_names[kind],
                        parameter_sets[parameter_index].name,
                        parameter_sets[parameter_index].expected_cases[kind],
                        case_counts[parameter_index][kind]);
                ok = false;
            }
        }
    }
    if (total_cases != ACVP_CASE_COUNT)
    {
        fprintf(stderr, "expected %d ACVP cases, ran %zu\n", ACVP_CASE_COUNT, total_cases);
        ok = false;
    }

    OQS_destroy();
    if (ok)
    {
        printf("Validated %zu vendored NIST ACVP ML-DSA cases across ML-DSA-44/65/87.\n", total_cases);
    }
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
