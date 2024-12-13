/*
 *  Copyright (C) 2024 Fraunhofer AISEC
 *  Authors: Andrei-Cosmin Aprodu <andrei-cosmin.aprodu@aisec.fraunhofer.de>
 *
 *  EnclaveSGXUtils.cpp
 *
 *  Creates main enclave functionality.
 *
 *  All Rights Reserved.
 */

#include <cstring>

#include "EnclaveSGXUtils.h"


static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        ""
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        ""
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        ""
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        ""
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        ""
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        ""
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        ""
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        ""
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        ""
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        ""
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        ""
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        ""
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        ""
    },
};

size_t extract_stack_base() {
    auto *thread_data = reinterpret_cast<thread_data_stripped_t *>(sgx_thread_self());
    return thread_data->stack_base_addr;
}

size_t extract_stack_size() {
    auto *thread_data = reinterpret_cast<thread_data_stripped_t *>(sgx_thread_self());
    size_t base = thread_data->stack_base_addr;
    size_t limit = thread_data->stack_limit_addr;
    return base - limit;
}

void calculate_pow(const uint32_t *nonce, uint32_t *result, int difficulty) {
    sgx_sha256_hash_t digest = {0};
    uint8_t seed[8];
    std::memset(seed, 0, 8);
    *reinterpret_cast<uint32_t *>(seed) = *nonce;

    for (uint32_t i = 0; i < 0xffffffff; ++i) {
        *reinterpret_cast<uint32_t *>(seed + 4) = i;
        int local_difficulty = difficulty;

        if (SGX_SUCCESS != sgx_sha256_msg(seed, 8, &digest)) {
            LOG(2, "Error during proof-of-work computation!");
            *result = 0;
            return;
        }

        bool correct_seed = true;
        uint32_t hash_index = 0;
        while (local_difficulty >= 8) {
            if (digest[hash_index++] != 0) {
                correct_seed = false;
                break;
            }
            local_difficulty -= 8;
        }
        if (correct_seed && local_difficulty > 0 && digest[hash_index] >> (8 - local_difficulty) != 0) {
            continue;
        }
        if (correct_seed) {
            *result = i;
            i = 0;
            break;
        }
    }
}

void trigger_pow(bool trigger_worker, bool *halt_worker, uint32_t *watcher_nonce, uint32_t *watcher_result) {
    if (trigger_worker) {
        if (!*halt_worker) {
            *halt_worker = true;
        }
    }
    calculate_pow(watcher_nonce, watcher_result, WATCHER_POW_DIFFICULTY);
}

void print_error_message(const std::string &message, sgx_status_t ret) {
    LOG(2, message);

    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if (ret == sgx_errlist[idx].err) {
            if (sgx_errlist[idx].sug != "") {
                ocall_print_string(std::string(">>> Suggestion: " + sgx_errlist[idx].sug).c_str());
            }
            ocall_print_string(std::string("\033[1;31m>>> " + sgx_errlist[idx].msg + "\033[0m").c_str());
            break;
        }
    }
}

void setup_log_level(short level) {
    min_log_level = level;
}
