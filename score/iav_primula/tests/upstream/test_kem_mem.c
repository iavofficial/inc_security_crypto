// SPDX-License-Identifier: MIT

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#include "tmp_store.h"
#include "test_helpers.h"

typedef struct magic_s {
	uint8_t val[32];
} magic_t;

typedef enum kem_ops {
	KEM_KEYGEN    = 0,
	KEM_ENCAPS    = 1,
	KEM_DECAPS    = 2
} KEM_OPS;

static OQS_STATUS kem_test_correctness(const char *method_name, KEM_OPS op) {

	OQS_KEM *kem = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *ciphertext = NULL;
	uint8_t *shared_secret_e = NULL;
	uint8_t *shared_secret_d = NULL;
	OQS_STATUS rc, ret = OQS_ERROR;
	int rv;
	size_t retlen;

	kem = OQS_KEM_new(method_name);
	if (kem == NULL) {
		fprintf(stderr, "ERROR: OQS_KEM_new failed\n");
		goto err;
	}

	switch (op) {
	case KEM_KEYGEN:
		printf("================================================================================\n");
		printf("Executing keygen for KEM %s\n", kem->method_name);
		printf("Version source: %s\n", kem->alg_version);
		printf("================================================================================\n");

		public_key = OQS_MEM_malloc(kem->length_public_key);
		secret_key = OQS_MEM_malloc(kem->length_secret_key);

		if ((public_key == NULL) || (secret_key == NULL)) {
			fprintf(stderr, "ERROR: OQS_MEM_malloc failed\n");
			goto err;
		}

		rc = OQS_KEM_keypair(kem, public_key, secret_key);
		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_KEM_keypair failed\n");
			goto err;
		}
		if (oqs_fstore("pk", method_name, public_key, kem->length_public_key) != OQS_SUCCESS) {
			goto err;
		}
		if (oqs_fstore("sk", method_name, secret_key, kem->length_secret_key) != OQS_SUCCESS) {
			goto err;
		}
		ret = OQS_SUCCESS;
		goto cleanup;

	case KEM_ENCAPS:
		printf("================================================================================\n");
		printf("Executing encaps for KEM %s\n", kem->method_name);
		printf("Version source: %s\n", kem->alg_version);
		printf("================================================================================\n");

		public_key = OQS_MEM_malloc(kem->length_public_key);
		secret_key = OQS_MEM_malloc(kem->length_secret_key);
		ciphertext = OQS_MEM_malloc(kem->length_ciphertext);
		shared_secret_e = OQS_MEM_malloc(kem->length_shared_secret);

		if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) || (shared_secret_e == NULL)) {
			fprintf(stderr, "ERROR: OQS_MEM_malloc failed\n");
			goto err;
		}

		if (oqs_fload("pk", method_name, public_key, kem->length_public_key, &retlen) != OQS_SUCCESS) {
			goto err;
		}
		if (oqs_fload("sk", method_name, secret_key, kem->length_secret_key, &retlen) != OQS_SUCCESS) {
			goto err;
		}
		rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_KEM_encaps failed\n");
			goto err;
		}
		if (oqs_fstore("ct", method_name, ciphertext, kem->length_ciphertext) != OQS_SUCCESS) {
			goto err;
		}
		if (oqs_fstore("se", method_name, shared_secret_e, kem->length_shared_secret) != OQS_SUCCESS) {
			goto err;
		}
		ret = OQS_SUCCESS;
		goto cleanup;

	case KEM_DECAPS:
		printf("================================================================================\n");
		printf("Executing decaps for KEM %s\n", kem->method_name);
		printf("Version source: %s\n", kem->alg_version);
		printf("================================================================================\n");

		public_key = OQS_MEM_malloc(kem->length_public_key);
		secret_key = OQS_MEM_malloc(kem->length_secret_key);
		ciphertext = OQS_MEM_malloc(kem->length_ciphertext);
		shared_secret_e = OQS_MEM_malloc(kem->length_shared_secret);
		shared_secret_d = OQS_MEM_malloc(kem->length_shared_secret);

		if ((public_key == NULL) || (secret_key == NULL) || (ciphertext == NULL) || (shared_secret_e == NULL) || (shared_secret_d == NULL)) {
			fprintf(stderr, "ERROR: OQS_MEM_malloc failed\n");
			goto err;
		}
		if (oqs_fload("pk", method_name, public_key, kem->length_public_key, &retlen) != OQS_SUCCESS) {
			goto err;
		}
		if (oqs_fload("sk", method_name, secret_key, kem->length_secret_key, &retlen) != OQS_SUCCESS) {
			goto err;
		}
		if (oqs_fload("ct", method_name, ciphertext, kem->length_ciphertext, &retlen) != OQS_SUCCESS) {
			goto err;
		}
		if (oqs_fload("se", method_name, shared_secret_e, kem->length_shared_secret, &retlen) != OQS_SUCCESS) {
			goto err;
		}

		rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
		if (rc != OQS_SUCCESS) {
			fprintf(stderr, "ERROR: OQS_KEM_decaps failed\n");
			goto err;
		}

		rv = memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret);
		if (rv != 0) {
			fprintf(stderr, "ERROR: shared secrets are not equal\n");
			OQS_print_hex_string("shared_secret_e", shared_secret_e, kem->length_shared_secret);
			OQS_print_hex_string("shared_secret_d", shared_secret_d, kem->length_shared_secret);
			goto err;
		} else {
			printf("shared secrets are equal\n");
		}
		ret = OQS_SUCCESS;
		goto cleanup;

	default:
		fprintf(stderr, "Incorrect operation requested. Aborting.\n");
		goto err;
	}


err:
	ret = OQS_ERROR;

cleanup:
	if (kem != NULL) {
		OQS_MEM_secure_free(secret_key, kem->length_secret_key);
		OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
		OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
	}
	if (public_key) {
		OQS_MEM_insecure_free(public_key);
	}
	if (ciphertext) {
		OQS_MEM_insecure_free(ciphertext);
	}
	OQS_KEM_free(kem);

	return ret;
}

int main(void) {
	static const char *const algorithms[] = {
		OQS_KEM_alg_ml_kem_512,
		OQS_KEM_alg_ml_kem_768,
		OQS_KEM_alg_ml_kem_1024,
	};
	int exit_code = EXIT_FAILURE;
	bool store_initialized = false;

	OQS_init();

	// Use system RNG in this program
	if (OQS_randombytes_switch_algorithm(OQS_RAND_alg_system) != OQS_SUCCESS) {
		printf("Could not generate random data with system RNG\n");
		goto cleanup;
	}

	if (oqs_fstore_init() != OQS_SUCCESS) {
		fprintf(stderr, "Could not create isolated test storage\n");
		goto cleanup;
	}
	store_initialized = true;

	for (size_t i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); ++i) {
		const char *alg_name = algorithms[i];
		if (!OQS_KEM_alg_is_enabled(alg_name)) {
			fprintf(stderr, "KEM algorithm %s is not enabled\n", alg_name);
			goto cleanup;
		}
		for (KEM_OPS op = KEM_KEYGEN; op <= KEM_DECAPS; ++op) {
			if (kem_test_correctness(alg_name, op) != OQS_SUCCESS) {
				goto cleanup;
			}
		}
	}

	exit_code = EXIT_SUCCESS;

cleanup:
	if (store_initialized && oqs_fstore_cleanup() != OQS_SUCCESS) {
		fprintf(stderr, "Could not remove isolated test storage\n");
		exit_code = EXIT_FAILURE;
	}
	OQS_destroy();
	return exit_code;
}
