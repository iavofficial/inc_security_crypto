// SPDX-License-Identifier: MIT

#define _XOPEN_SOURCE 700

#include "tmp_store.h"

#include <dirent.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char* store_directory = NULL;

static char* make_store_path(const char* fname, const char* mname)
{
    const bool is_entry_path = (mname == NULL) || (mname[0] == '\0');
    const size_t path_len =
        strlen(store_directory) + strlen(mname == NULL ? "" : mname) + strlen(fname) + (is_entry_path ? 2U : 3U);
    char* const path = (char*)malloc(path_len);
    if (path == NULL)
    {
        return NULL;
    }
    const int written = is_entry_path ? snprintf(path, path_len, "%s/%s", store_directory, fname)
                                      : snprintf(path, path_len, "%s/%s-%s", store_directory, mname, fname);
    if ((written < 0) || ((size_t)written >= path_len))
    {
        free(path);
        return NULL;
    }
    return path;
}

OQS_STATUS oqs_fstore_init(void)
{
    const char* const test_tmpdir = getenv("TEST_TMPDIR");
    if ((test_tmpdir == NULL) || (test_tmpdir[0] == '\0') || (store_directory != NULL))
    {
        return OQS_ERROR;
    }

    const size_t template_len = strlen(test_tmpdir) + sizeof("/iav-primula-oqs-test-XXXXXX");
    store_directory = (char*)malloc(template_len);
    if (store_directory == NULL)
    {
        return OQS_ERROR;
    }
    const int written = snprintf(store_directory, template_len, "%s/iav-primula-oqs-test-XXXXXX", test_tmpdir);
    if ((written < 0) || ((size_t)written >= template_len) || (mkdtemp(store_directory) == NULL))
    {
        free(store_directory);
        store_directory = NULL;
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

OQS_STATUS oqs_fstore(const char* fname, const char* mname, const uint8_t* data, size_t len)
{
    if ((store_directory == NULL) || (fname == NULL) || (mname == NULL) || (data == NULL))
    {
        return OQS_ERROR;
    }
    char* const path = make_store_path(fname, mname);
    if (path == NULL)
    {
        return OQS_ERROR;
    }

    FILE* const file = fopen(path, "wb");
    free(path);
    if (file == NULL)
    {
        return OQS_ERROR;
    }
    const size_t written = fwrite(data, 1U, len, file);
    const int close_status = fclose(file);
    return ((written == len) && (close_status == 0)) ? OQS_SUCCESS : OQS_ERROR;
}

OQS_STATUS oqs_fload(const char* fname, const char* mname, uint8_t* data, size_t len, size_t* rcvd)
{
    if ((store_directory == NULL) || (fname == NULL) || (mname == NULL) || (data == NULL) || (rcvd == NULL))
    {
        return OQS_ERROR;
    }
    char* const path = make_store_path(fname, mname);
    if (path == NULL)
    {
        return OQS_ERROR;
    }

    FILE* const file = fopen(path, "rb");
    free(path);
    if (file == NULL)
    {
        return OQS_ERROR;
    }
    const size_t read_count = fread(data, 1U, len, file);
    const int trailing_byte = fgetc(file);
    const bool valid = (read_count == len) && (trailing_byte == EOF) && (ferror(file) == 0);
    const int close_status = fclose(file);
    *rcvd = read_count;
    return (valid && (close_status == 0)) ? OQS_SUCCESS : OQS_ERROR;
}

OQS_STATUS oqs_fstore_cleanup(void)
{
    if (store_directory == NULL)
    {
        return OQS_SUCCESS;
    }

    OQS_STATUS status = OQS_SUCCESS;
    DIR* const directory = opendir(store_directory);
    if (directory == NULL)
    {
        status = OQS_ERROR;
    }
    else
    {
        struct dirent* entry = NULL;
        while ((entry = readdir(directory)) != NULL)
        {
            if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0))
            {
                continue;
            }
            char* const path = make_store_path(entry->d_name, "");
            if ((path == NULL) || (unlink(path) != 0))
            {
                status = OQS_ERROR;
            }
            free(path);
        }
        if (closedir(directory) != 0)
        {
            status = OQS_ERROR;
        }
        if (rmdir(store_directory) != 0)
        {
            status = OQS_ERROR;
        }
    }

    free(store_directory);
    store_directory = NULL;
    return status;
}
