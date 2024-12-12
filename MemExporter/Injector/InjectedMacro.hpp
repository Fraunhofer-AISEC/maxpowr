// Halting logic to be called after most code lines of the Worker thread.
// This will stall execution in case the time for PoW has come.

#define HALT_CONDITION(should_halt, challenge, solution, mutex, mutex_cond) do { \
    if (*should_halt) { \
        LOG(0, "Worker PoW starting..."); \
        calculate_pow(challenge, solution, WORKER_POW_DIFFICULTY); \
        LOG(0, "Worker PoW finished!");  \
        *should_halt = false; \
        sgx_thread_mutex_lock(mutex); \
        sgx_thread_cond_broadcast(mutex_cond); \
        sgx_thread_mutex_unlock(mutex);} \
    } while (0)
