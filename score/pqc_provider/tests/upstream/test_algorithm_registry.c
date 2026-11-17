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

#include <oqs/oqs.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* const supported_signatures[] = {
    OQS_SIG_alg_ml_dsa_44,
    OQS_SIG_alg_ml_dsa_65,
    OQS_SIG_alg_ml_dsa_87,
};

static const char* const supported_kems[] = {
    OQS_KEM_alg_ml_kem_512,
    OQS_KEM_alg_ml_kem_768,
    OQS_KEM_alg_ml_kem_1024,
};

static bool is_supported(const char* const name, const char* const* const supported, const size_t supported_count)
{
    for (size_t i = 0; i < supported_count; ++i)
    {
        if (strcmp(name, supported[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool check_signature_registry(void)
{
    const int count = OQS_SIG_alg_count();
    if (count != (int)OQS_SIG_algs_length || count <= 0)
    {
        fprintf(stderr, "unexpected OQS signature registry size: %d\n", count);
        return false;
    }

    size_t enabled_count = 0;
    for (int i = 0; i < count; ++i)
    {
        const char* const name = OQS_SIG_alg_identifier((size_t)i);
        if (name == NULL || name[0] == '\0')
        {
            fprintf(stderr, "missing OQS signature identifier at index %d\n", i);
            return false;
        }

        const bool expected_enabled =
            is_supported(name, supported_signatures, sizeof(supported_signatures) / sizeof(supported_signatures[0]));
        const bool enabled = OQS_SIG_alg_is_enabled(name) == 1;
        if (enabled != expected_enabled)
        {
            fprintf(stderr, "unexpected enabled status for OQS signature %s\n", name);
            return false;
        }

        OQS_SIG* const signature = OQS_SIG_new(name);
        if ((signature != NULL) != expected_enabled)
        {
            fprintf(stderr, "unexpected constructor result for OQS signature %s\n", name);
            OQS_SIG_free(signature);
            return false;
        }
        if (signature != NULL)
        {
            ++enabled_count;
            if (!OQS_SIG_supports_ctx_str(name))
            {
                fprintf(stderr, "ML-DSA context-string capability was not reported for %s\n", name);
                OQS_SIG_free(signature);
                return false;
            }
        }
        OQS_SIG_free(signature);
    }

    if (enabled_count != sizeof(supported_signatures) / sizeof(supported_signatures[0]))
    {
        fprintf(stderr, "expected exactly three enabled ML-DSA variants, got %zu\n", enabled_count);
        return false;
    }
    if (OQS_SIG_alg_identifier((size_t)count) != NULL || OQS_SIG_alg_is_enabled(NULL) != 0 ||
        OQS_SIG_new(NULL) != NULL || OQS_SIG_supports_ctx_str(NULL) ||
        OQS_SIG_alg_is_enabled("not-an-oqs-signature") != 0 || OQS_SIG_new("not-an-oqs-signature") != NULL ||
        OQS_SIG_supports_ctx_str("not-an-oqs-signature"))
    {
        fprintf(stderr, "unexpected OQS signature registry boundary behavior\n");
        return false;
    }
    return true;
}

static bool check_kem_registry(void)
{
    const int count = OQS_KEM_alg_count();
    if (count != (int)OQS_KEM_algs_length || count <= 0)
    {
        fprintf(stderr, "unexpected OQS KEM registry size: %d\n", count);
        return false;
    }

    size_t enabled_count = 0;
    for (int i = 0; i < count; ++i)
    {
        const char* const name = OQS_KEM_alg_identifier((size_t)i);
        if (name == NULL || name[0] == '\0')
        {
            fprintf(stderr, "missing OQS KEM identifier at index %d\n", i);
            return false;
        }

        const bool expected_enabled =
            is_supported(name, supported_kems, sizeof(supported_kems) / sizeof(supported_kems[0]));
        const bool enabled = OQS_KEM_alg_is_enabled(name) == 1;
        if (enabled != expected_enabled)
        {
            fprintf(stderr, "unexpected enabled status for OQS KEM %s\n", name);
            return false;
        }

        OQS_KEM* const kem = OQS_KEM_new(name);
        if ((kem != NULL) != expected_enabled)
        {
            fprintf(stderr, "unexpected constructor result for OQS KEM %s\n", name);
            OQS_KEM_free(kem);
            return false;
        }
        if (kem != NULL)
        {
            ++enabled_count;
        }
        OQS_KEM_free(kem);
    }

    if (enabled_count != sizeof(supported_kems) / sizeof(supported_kems[0]))
    {
        fprintf(stderr, "expected exactly three enabled ML-KEM variants, got %zu\n", enabled_count);
        return false;
    }
    if (OQS_KEM_alg_identifier((size_t)count) != NULL || OQS_KEM_alg_is_enabled(NULL) != 0 ||
        OQS_KEM_new(NULL) != NULL || OQS_KEM_alg_is_enabled("not-an-oqs-kem") != 0 ||
        OQS_KEM_new("not-an-oqs-kem") != NULL)
    {
        fprintf(stderr, "unexpected OQS KEM registry boundary behavior\n");
        return false;
    }
    return true;
}

int main(void)
{
    OQS_init();
    const bool passed = check_signature_registry() && check_kem_registry();
    OQS_destroy();
    return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
