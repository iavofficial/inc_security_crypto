// SPDX-License-Identifier: MIT
#ifndef IAV_PRIMULA_LIBOQS_TMP_STORE_H
#define IAV_PRIMULA_LIBOQS_TMP_STORE_H

#include <stddef.h>
#include <stdint.h>

#include <oqs/oqs.h>

OQS_STATUS oqs_fstore_init(void);
OQS_STATUS oqs_fstore(const char* fname, const char* mname, const uint8_t* data, size_t len);
OQS_STATUS oqs_fload(const char* fname, const char* mname, uint8_t* data, size_t len, size_t* rcvd);
OQS_STATUS oqs_fstore_cleanup(void);

#endif  // IAV_PRIMULA_LIBOQS_TMP_STORE_H
