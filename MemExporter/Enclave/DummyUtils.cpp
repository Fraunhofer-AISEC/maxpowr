/*
 *  Copyright (C) 2024 Fraunhofer AISEC
 *  Authors: Andrei-Cosmin Aprodu <andrei-cosmin.aprodu@aisec.fraunhofer.de>
 *
 *  DummyUtils.cpp
 *
 *  Creates dummy data for demonstration.
 *
 *  All Rights Reserved.
 */

#include "EnclaveSGXUtils.h"
#include "DummyUtils.h"


void dummy_subtask1_(bool *should_halt, uint32_t *challenge, uint32_t *solution,
    sgx_thread_mutex_t *mutex, sgx_thread_cond_t *mutex_cond) {
    LOG(-1, "Subtask 1.");

    char dummy_mem[] = "---subtask1_AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHH---";
    (void) dummy_mem;
    
    for (int i = 0; i < 30000000; ++i) {
        i = i + 1;
        i = i - 1;
    }
}

void dummy_subtask2_(bool *should_halt, uint32_t *challenge, uint32_t *solution,
    sgx_thread_mutex_t *mutex, sgx_thread_cond_t *mutex_cond) {
    LOG(-1, "Subtask 2.");

    char dummy_mem[] = "---subtask2_AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHH---";
    (void) dummy_mem;

    for (int i = 0; i < 30000000; ++i) {
        i = i + 2;
        i = i - 2;
    }
}

void dummy_task_long(bool *should_halt, size_t *target_base, size_t *target_size, 
    uint32_t *challenge, uint32_t *solution, sgx_thread_mutex_t *mutex, sgx_thread_cond_t *mutex_cond) {
    LOG(1, "Running dummy task...");

    // Setup stack bounds
    *target_base = extract_stack_base();
    *target_size = extract_stack_size();

    // Allocate some memory on the stack
    char dummy_mem[] = "---task_AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHH---";
    (void) dummy_mem;

    // Execute "long" task
    for (int i = 0; i < 10000000; ++i) {
        bool div80000 = i % 80000;
        bool div50000 = i % 50000;

        if (div80000 == 0) {
            dummy_subtask1_(should_halt, challenge, solution, mutex, mutex_cond);
        }
        if (div50000 == 0) {
            dummy_subtask2_(should_halt, challenge, solution, mutex, mutex_cond);
        }

        i = i + 3;
        i = i - 3;
    }

    // Clear stack bounds to signal stopping
    *target_base = 0;
    *target_size = 0;

    LOG(1, "Dummy task finished!");
}
