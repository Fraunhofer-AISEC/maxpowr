/*
 *  Copyright (C) 2024 Fraunhofer AISEC
 *  Authors: Andrei-Cosmin Aprodu <andrei-cosmin.aprodu@aisec.fraunhofer.de>
 *
 *  Enclave.cpp
 *
 *  Creates main enclave functionality.
 *
 *  All Rights Reserved.
 */

#include <string>
#include <cstring>
#include <climits>

#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "sgx_thread.h"
#include "KeyMaterial.h"
#include "Enclave.h"


bool append_flag = false;
short min_log_level = 1;
uint32_t num_watchers = 1;
bool halt_worker = false;
uint32_t worker_pow_challenge = 0;
uint32_t worker_pow_solution = 0;
uint32_t *watcher_pow_solutions = nullptr;
uint32_t *watcher_rand = nullptr;

uint32_t snapshot_count = 0;
uint32_t key_count = 0;
uint8_t *symmetric_key_raw = nullptr;

Accumulator accumulator;
sgx_thread_mutex_t mutex = SGX_THREAD_NONRECURSIVE_MUTEX_INITIALIZER;
sgx_thread_cond_t mutex_cond = SGX_THREAD_COND_INITIALIZER;
sgx_thread_mutexattr_t mutex_attr = {0};
unsigned long target_base = 0;
unsigned long target_size = 0;


void initialize_mutex() {
    sgx_thread_mutex_init(&mutex, &mutex_attr);
}

void destroy_mutex() {
    sgx_thread_mutex_destroy(&mutex);
}

void initialize_capture(short log_level, uint32_t watchers) {
    setup_log_level(log_level);

    num_watchers = watchers;
    watcher_pow_solutions = new uint32_t[num_watchers];
    watcher_rand = new uint32_t[num_watchers];

    accumulator.set_limit(num_watchers);

    // Generate new symmetric key
    symmetric_key_raw = new sgx_aes_gcm_128bit_key_t;
    sgx_read_rand(symmetric_key_raw, SGX_AESGCM_KEY_SIZE);

    // Send newly-generated symmetric key encrypted with RSA-3072
    size_t rsa_bytes = 384;
    void *public_key;

    Buffer<unsigned char> n(p_n, static_cast<uint32_t>(rsa_bytes));
    Buffer<unsigned char> rsa_cipher(static_cast<uint32_t>(rsa_bytes));
    
    sgx_status_t sgx_res = sgx_create_rsa_pub1_key(n.size(), sizeof(e), n.data(), reinterpret_cast<unsigned char *>(&e), &public_key);

    if (sgx_res != SGX_SUCCESS) {
        print_error_message("Public key generation failed", sgx_res);
    }

    sgx_res = sgx_rsa_pub_encrypt_sha256(public_key, rsa_cipher.data(), &rsa_bytes, static_cast<unsigned char *>(symmetric_key_raw), SGX_AESGCM_KEY_SIZE);

    if (sgx_res != SGX_SUCCESS) {
        print_error_message("RSA encryption failed", sgx_res);
    } else {
        ocall_write_enc_sym_key(rsa_cipher.data());
        ++key_count;
    }
}

void end_capture() {
    delete[] symmetric_key_raw;
    delete[] watcher_pow_solutions;
    delete[] watcher_rand;
}

bool capture_stackshot(uint32_t id_watcher, uint32_t pow_challenge) {
    unsigned long base, size;

    // Target_base and target_size initialized by the worker thread
    if (target_base == 0 || target_size == 0) {
        LOG(2, "(" + std::to_string(id_watcher) + ") could not target worker thread!");
        return false;
    }

    append_flag = false;
    base = target_base;
    size = target_size;

    StackCrawler crawler(base, size);

    accumulator.wait();

    // Give the worker a hard PoW problem and the watchers an easier one
    uint32_t intermediate_solution;
    trigger_pow(true, &halt_worker, &pow_challenge, &intermediate_solution);

    // After finishing the PoW challenge, scan and hash worker's stack
    crawler.crawl(intermediate_solution);
    intermediate_solution = 0;

    // Trigger second PoW for the watchers after hashing is done. Note that, for this proof-of-concept, we implemented
    // a naive PoW function which only manipulates integers. Therefore, we truncated the hash of the snapshot to accomodate
    // its signature. This should not be implemented in practice! Adapt the PoW function to accomodate the entire hash as seed!
    trigger_pow(false, &halt_worker, reinterpret_cast<uint32_t *>(crawler.get_hash()), &watcher_pow_solutions[id_watcher]);

    sgx_thread_mutex_lock(&mutex);
    ocall_write_watcher_metadata(pow_challenge, watcher_pow_solutions[id_watcher], append_flag);
    append_flag = true;
    sgx_thread_mutex_unlock(&mutex);
    watcher_pow_solutions[id_watcher] = 0;

    // Generate random number. The thread which ends up with the largest number prints the snapshot
    sgx_read_rand(reinterpret_cast<unsigned char *>(&watcher_rand[id_watcher]), sizeof(uint32_t));

    accumulator.wait();

    // Only one thread will export the information. This will be determined by the first byte of the resulting hash
    if (id_watcher == std::distance(watcher_rand, std::max_element(watcher_rand, watcher_rand + num_watchers))) {
        LOG(0, "(" + std::to_string(id_watcher) + ") outputs snapshot.");

        // Send snapshot encrypted with AES-128-GCM
        // Note: As additional associated data, we use the payload count, or dump count.
        //       This will be also referred to as 'Payload ID'. The Payload ID of the
        //       current symmetric key will be called Key ID.
        unsigned char iv_raw[SGX_AESGCM_IV_SIZE];
        sgx_read_rand(iv_raw, SGX_AESGCM_IV_SIZE);

        Buffer<uint8_t> symmetric_key(symmetric_key_raw, SGX_AESGCM_KEY_SIZE);
        Buffer<uint8_t> plaintext(reinterpret_cast<uint8_t *>(const_cast<char *>(crawler.dump())), crawler.snapshot_length());
        Buffer<uint8_t> aes_cipher(SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + plaintext.size());
        Buffer<uint8_t> iv(iv_raw, SGX_AESGCM_IV_SIZE);
        Buffer<uint8_t> aad(reinterpret_cast<uint8_t *>(&snapshot_count), sizeof(snapshot_count));
        Buffer<uint8_t> mac(SGX_AESGCM_MAC_SIZE);

        sgx_status_t sgx_res = sgx_rijndael128GCM_encrypt(reinterpret_cast<sgx_aes_gcm_128bit_key_t *>(symmetric_key.data()),
                                plaintext.data(), plaintext.size(),
                                aes_cipher.data(),
                                iv.data(), iv.size(),
                                aad.data(), aad.size(),
                                reinterpret_cast<sgx_aes_gcm_128bit_tag_t *>(mac.data()));

        if (sgx_res != SGX_SUCCESS) {
            print_error_message("AES-GCM encryption failed", sgx_res);
        } else {
            ocall_write_stackshot(aes_cipher.data(), aes_cipher.size());
            ocall_write_mac_iv(mac.data(), iv.data());
            LOG(1, "Generated \"" + std::to_string(key_count) + "_" + std::to_string(snapshot_count) + ".stackshot\".");
        }

        // Wait for Worker to finish with the PoW challenge, then output its PoW result
        sgx_thread_mutex_lock(&mutex);
        while (halt_worker) {
            sgx_thread_cond_wait(&mutex_cond, &mutex);
        }
        sgx_thread_mutex_unlock(&mutex);

        ocall_write_worker_metadata(worker_pow_challenge, worker_pow_solution);

        ocall_increment_count();
        snapshot_count++;

        // If counter overflows, we must generate a new symmetric key
        if (snapshot_count >= INT_MAX) {
            ocall_reset_count();
            snapshot_count = 0;
            end_capture();
            initialize_capture(min_log_level, num_watchers);
        }
    } else {
        // Wait for Worker to finish with the PoW challenge
        sgx_thread_mutex_lock(&mutex);
        while (halt_worker) {
            sgx_thread_cond_wait(&mutex_cond, &mutex);
        }
        sgx_thread_mutex_unlock(&mutex);
    }

    return true;
}

void set_new_worker_challenge(uint32_t pow_challenge) {
    worker_pow_challenge = pow_challenge;
}

void trigger_worker_task() {
    // Start a 'long' computation task
    dummy_task_long(&halt_worker, &target_base, &target_size, &worker_pow_challenge, &worker_pow_solution, &mutex, &mutex_cond);
}
