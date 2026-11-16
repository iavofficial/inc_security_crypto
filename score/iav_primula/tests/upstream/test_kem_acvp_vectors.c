// SPDX-License-Identifier: MIT

#include <oqs/oqs.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ACVP_CASE_COUNT 225
#define MAX_VECTOR_LINE 65536
#define MLKEM_SEED_BYTES 64
#define MLKEM_ENCAP_SEED_BYTES 32

typedef enum
{
    CASE_KEYGEN = 0,
    CASE_ENCAPS,
    CASE_DECAPS,
    CASE_ENCAPS_KEY_CHECK,
    CASE_DECAPS_KEY_CHECK,
    CASE_KIND_COUNT,
} case_kind_t;

typedef struct
{
    const char* name;
    const char* oqs_name;
    size_t expected_count[CASE_KIND_COUNT];
} parameter_set_t;

static const parameter_set_t parameter_sets[] = {
    {"ML-KEM-512", OQS_KEM_alg_ml_kem_512, {25, 25, 10, 5, 10}},
    {"ML-KEM-768", OQS_KEM_alg_ml_kem_768, {25, 25, 10, 5, 10}},
    {"ML-KEM-1024", OQS_KEM_alg_ml_kem_1024, {25, 25, 10, 5, 10}},
};

static const char* const case_names[CASE_KIND_COUNT] = {
    "keygen",
    "encaps",
    "decaps",
    "encaps_key_check",
    "decaps_key_check",
};

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

static bool parse_u32(const char* text, uint32_t* value)
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

static bool split_fields(char* line, char** fields, size_t capacity, size_t* count)
{
    *count = 0;
    if (line[0] == '\0')
    {
        return false;
    }
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
    for (size_t i = 0; i < *count; ++i)
    {
        if (fields[i][0] == '\0')
        {
            return false;
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

static bool decode_hex(const char* text, uint8_t* output, size_t output_length)
{
    if (strlen(text) != output_length * 2)
    {
        return false;
    }
    for (size_t i = 0; i < output_length; ++i)
    {
        int high = hex_nibble(text[2 * i]);
        int low = hex_nibble(text[2 * i + 1]);
        if (high < 0 || low < 0)
        {
            return false;
        }
        output[i] = (uint8_t)((high << 4) | low);
    }
    return true;
}

static uint8_t* decode_alloc(const char* text, size_t length)
{
    uint8_t* bytes = OQS_MEM_malloc(length);
    if (bytes == NULL)
    {
        return NULL;
    }
    if (!decode_hex(text, bytes, length))
    {
        OQS_MEM_secure_free(bytes, length);
        return NULL;
    }
    return bytes;
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

static bool expect_status(OQS_STATUS status,
                          bool expected_success,
                          const char* operation,
                          const char* parameter_set,
                          uint32_t tc_id)
{
    bool succeeded = status == OQS_SUCCESS;
    if (succeeded != expected_success)
    {
        fprintf(stderr,
                "ACVP %s %s tcId=%u: expected %s, got OQS_STATUS %d\n",
                operation,
                parameter_set,
                tc_id,
                expected_success ? "success" : "failure",
                (int)status);
        return false;
    }
    return true;
}

static bool run_case(case_kind_t kind, const parameter_set_t* parameter_set, const char* const* fields, uint32_t tc_id)
{
    bool passed = false;
    OQS_KEM* kem = OQS_KEM_new(parameter_set->oqs_name);
    uint8_t* seed = NULL;
    uint8_t* public_key = NULL;
    uint8_t* secret_key = NULL;
    uint8_t* ciphertext = NULL;
    uint8_t* expected_ciphertext = NULL;
    uint8_t* shared_secret = NULL;
    uint8_t* expected_shared_secret = NULL;
    uint8_t encaps_seed[MLKEM_ENCAP_SEED_BYTES] = {0};
    bool expected_success = false;
    OQS_STATUS status;

    if (kem == NULL)
    {
        fprintf(stderr, "ACVP %s: liboqs did not enable %s\n", case_names[kind], parameter_set->name);
        return false;
    }

    switch (kind)
    {
        case CASE_KEYGEN:
            seed = decode_alloc(fields[0], MLKEM_SEED_BYTES);
            public_key = decode_alloc(fields[1], kem->length_public_key);
            secret_key = decode_alloc(fields[2], kem->length_secret_key);
            if (seed == NULL || public_key == NULL || secret_key == NULL)
            {
                fprintf(stderr,
                        "ACVP keygen %s tcId=%u: malformed vector or allocation failure\n",
                        parameter_set->name,
                        tc_id);
                goto cleanup;
            }
            {
                uint8_t* actual_public_key = OQS_MEM_malloc(kem->length_public_key);
                uint8_t* actual_secret_key = OQS_MEM_malloc(kem->length_secret_key);
                if (actual_public_key == NULL || actual_secret_key == NULL)
                {
                    fprintf(stderr, "ACVP keygen %s tcId=%u: allocation failure\n", parameter_set->name, tc_id);
                    free_buffer(actual_public_key, kem->length_public_key, false);
                    free_buffer(actual_secret_key, kem->length_secret_key, true);
                    goto cleanup;
                }
                status = OQS_KEM_keypair_derand(kem, actual_public_key, actual_secret_key, seed);
                passed = status == OQS_SUCCESS && memcmp(actual_public_key, public_key, kem->length_public_key) == 0 &&
                         memcmp(actual_secret_key, secret_key, kem->length_secret_key) == 0;
                if (!passed)
                {
                    fprintf(stderr,
                            "ACVP keygen %s tcId=%u: key pair mismatch or operation failure\n",
                            parameter_set->name,
                            tc_id);
                }
                free_buffer(actual_public_key, kem->length_public_key, false);
                free_buffer(actual_secret_key, kem->length_secret_key, true);
            }
            break;

        case CASE_ENCAPS:
            seed = decode_alloc(fields[0], kem->length_encaps_seed);
            public_key = decode_alloc(fields[1], kem->length_public_key);
            expected_shared_secret = decode_alloc(fields[2], kem->length_shared_secret);
            expected_ciphertext = decode_alloc(fields[3], kem->length_ciphertext);
            if (seed == NULL || public_key == NULL || expected_shared_secret == NULL || expected_ciphertext == NULL)
            {
                fprintf(stderr,
                        "ACVP encaps %s tcId=%u: malformed vector or allocation failure\n",
                        parameter_set->name,
                        tc_id);
                goto cleanup;
            }
            ciphertext = OQS_MEM_malloc(kem->length_ciphertext);
            shared_secret = OQS_MEM_malloc(kem->length_shared_secret);
            if (ciphertext == NULL || shared_secret == NULL)
            {
                fprintf(stderr, "ACVP encaps %s tcId=%u: allocation failure\n", parameter_set->name, tc_id);
                goto cleanup;
            }
            status = OQS_KEM_encaps_derand(kem, ciphertext, shared_secret, public_key, seed);
            passed = status == OQS_SUCCESS && memcmp(ciphertext, expected_ciphertext, kem->length_ciphertext) == 0 &&
                     memcmp(shared_secret, expected_shared_secret, kem->length_shared_secret) == 0;
            if (!passed)
            {
                fprintf(stderr,
                        "ACVP encaps %s tcId=%u: ciphertext/shared-secret mismatch or operation failure\n",
                        parameter_set->name,
                        tc_id);
            }
            break;

        case CASE_DECAPS:
            secret_key = decode_alloc(fields[0], kem->length_secret_key);
            ciphertext = decode_alloc(fields[1], kem->length_ciphertext);
            expected_shared_secret = decode_alloc(fields[2], kem->length_shared_secret);
            if (secret_key == NULL || ciphertext == NULL || expected_shared_secret == NULL)
            {
                fprintf(stderr,
                        "ACVP decaps %s tcId=%u: malformed vector or allocation failure\n",
                        parameter_set->name,
                        tc_id);
                goto cleanup;
            }
            shared_secret = OQS_MEM_malloc(kem->length_shared_secret);
            if (shared_secret == NULL)
            {
                fprintf(stderr, "ACVP decaps %s tcId=%u: allocation failure\n", parameter_set->name, tc_id);
                goto cleanup;
            }
            status = OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
            passed =
                status == OQS_SUCCESS && memcmp(shared_secret, expected_shared_secret, kem->length_shared_secret) == 0;
            if (!passed)
            {
                fprintf(stderr,
                        "ACVP decaps %s tcId=%u: shared-secret mismatch or operation failure\n",
                        parameter_set->name,
                        tc_id);
            }
            break;

        case CASE_ENCAPS_KEY_CHECK:
            public_key = decode_alloc(fields[0], kem->length_public_key);
            if (public_key == NULL || (strcmp(fields[1], "0") != 0 && strcmp(fields[1], "1") != 0))
            {
                fprintf(
                    stderr, "ACVP encapsulationKeyCheck %s tcId=%u: malformed vector\n", parameter_set->name, tc_id);
                goto cleanup;
            }
            expected_success = fields[1][0] == '1';
            ciphertext = OQS_MEM_malloc(kem->length_ciphertext);
            shared_secret = OQS_MEM_malloc(kem->length_shared_secret);
            if (ciphertext == NULL || shared_secret == NULL)
            {
                fprintf(
                    stderr, "ACVP encapsulationKeyCheck %s tcId=%u: allocation failure\n", parameter_set->name, tc_id);
                goto cleanup;
            }
            status = OQS_KEM_encaps_derand(kem, ciphertext, shared_secret, public_key, encaps_seed);
            passed = expect_status(status, expected_success, "encapsulationKeyCheck", parameter_set->name, tc_id);
            break;

        case CASE_DECAPS_KEY_CHECK:
            public_key = decode_alloc(fields[0], kem->length_public_key);
            secret_key = decode_alloc(fields[1], kem->length_secret_key);
            if (public_key == NULL || secret_key == NULL ||
                (strcmp(fields[2], "0") != 0 && strcmp(fields[2], "1") != 0))
            {
                fprintf(
                    stderr, "ACVP decapsulationKeyCheck %s tcId=%u: malformed vector\n", parameter_set->name, tc_id);
                goto cleanup;
            }
            expected_success = fields[2][0] == '1';
            ciphertext = OQS_MEM_malloc(kem->length_ciphertext);
            shared_secret = OQS_MEM_malloc(kem->length_shared_secret);
            expected_shared_secret = OQS_MEM_malloc(kem->length_shared_secret);
            if (ciphertext == NULL || shared_secret == NULL || expected_shared_secret == NULL)
            {
                fprintf(
                    stderr, "ACVP decapsulationKeyCheck %s tcId=%u: allocation failure\n", parameter_set->name, tc_id);
                goto cleanup;
            }
            status = OQS_KEM_encaps_derand(kem, ciphertext, expected_shared_secret, public_key, encaps_seed);
            if (status != OQS_SUCCESS)
            {
                fprintf(stderr,
                        "ACVP decapsulationKeyCheck %s tcId=%u: fixture public key was rejected\n",
                        parameter_set->name,
                        tc_id);
                goto cleanup;
            }
            status = OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
            passed = expect_status(status, expected_success, "decapsulationKeyCheck", parameter_set->name, tc_id);
            if (passed && expected_success &&
                memcmp(shared_secret, expected_shared_secret, kem->length_shared_secret) != 0)
            {
                fprintf(stderr,
                        "ACVP decapsulationKeyCheck %s tcId=%u: derived shared-secret mismatch\n",
                        parameter_set->name,
                        tc_id);
                passed = false;
            }
            break;

        default:
            fprintf(stderr, "unknown ACVP case kind\n");
            break;
    }

cleanup:
    free_buffer(seed, kind == CASE_ENCAPS ? kem->length_encaps_seed : MLKEM_SEED_BYTES, true);
    free_buffer(public_key, kem->length_public_key, false);
    free_buffer(secret_key, kem->length_secret_key, true);
    free_buffer(ciphertext, kem->length_ciphertext, false);
    free_buffer(expected_ciphertext, kem->length_ciphertext, false);
    free_buffer(shared_secret, kem->length_shared_secret, true);
    free_buffer(expected_shared_secret, kem->length_shared_secret, true);
    OQS_KEM_free(kem);
    return passed;
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: test_kem_acvp_vectors VECTOR_TSV\n");
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
        if (line_length == 0 || line[line_length - 1] != '\n')
        {
            fprintf(stderr, "ACVP vector line is empty or exceeds %d bytes\n", MAX_VECTOR_LINE - 1);
            ok = false;
            break;
        }
        line[line_length - 1] = '\0';
        char* fields[8];
        size_t field_count = 0;
        if (!split_fields(line, fields, sizeof(fields) / sizeof(fields[0]), &field_count) || field_count < 3)
        {
            fprintf(stderr, "malformed ACVP TSV row at line %zu\n", total_cases + 1);
            ok = false;
            break;
        }

        case_kind_t kind;
        size_t parameter_index = 0;
        uint32_t tc_id = 0;
        const parameter_set_t* parameter_set = NULL;
        if (!parse_case_kind(fields[0], &kind) ||
            (parameter_set = find_parameter_set(fields[1], &parameter_index)) == NULL || !parse_u32(fields[2], &tc_id))
        {
            fprintf(stderr, "invalid ACVP row identity at line %zu\n", total_cases + 1);
            ok = false;
            break;
        }

        size_t expected_fields = kind == CASE_KEYGEN || kind == CASE_DECAPS || kind == CASE_DECAPS_KEY_CHECK
                                     ? 6
                                     : (kind == CASE_ENCAPS ? 7 : 5);
        if (field_count != expected_fields)
        {
            fprintf(stderr,
                    "ACVP %s %s tcId=%u: expected %zu TSV columns, got %zu\n",
                    case_names[kind],
                    parameter_set->name,
                    tc_id,
                    expected_fields,
                    field_count);
            ok = false;
            break;
        }
        if (!run_case(kind, parameter_set, (const char* const*)&fields[3], tc_id))
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
            if (case_counts[parameter_index][kind] != parameter_sets[parameter_index].expected_count[kind])
            {
                fprintf(stderr,
                        "ACVP %s %s: expected %zu cases, ran %zu\n",
                        case_names[kind],
                        parameter_sets[parameter_index].name,
                        parameter_sets[parameter_index].expected_count[kind],
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
        printf("Validated %zu vendored NIST ACVP ML-KEM cases across ML-KEM-512/768/1024.\n", total_cases);
    }
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
