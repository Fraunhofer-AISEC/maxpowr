#pragma once


// Note: Pointer 'should_halt' is used by the automatically inserted macro of the '_gen' files.

void dummy_task_long(bool *should_halt, size_t *target_base, size_t *target_size, 
    uint32_t *challenge, uint32_t *solution, sgx_thread_mutex_t *mutex, sgx_thread_cond_t *mutex_cond);

void dummy_subtask1_(bool *should_halt, uint32_t *challenge, uint32_t *solution, 
    sgx_thread_mutex_t *mutex, sgx_thread_cond_t *mutex_cond);

void dummy_subtask2_(bool *should_halt, uint32_t *challenge, uint32_t *solution, 
    sgx_thread_mutex_t *mutex, sgx_thread_cond_t *mutex_cond);
