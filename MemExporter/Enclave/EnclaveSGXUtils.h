#pragma once


#include <string>
#include <algorithm>

#include "sgx_error.h"
#include "sgx_thread.h"
#include "sgx_tcrypto.h"
#include "Enclave_t.h"


#define WATCHER_POW_DIFFICULTY 8

#define WORKER_POW_DIFFICULTY 24

// lvl:
// - -1 = trace
// -  0 = debug
// -  1 = info
// -  2 = error
#define LOG(lvl, msg) do { \
    if (lvl == 2 && min_log_level <= 2) ocall_print_string(std::string("\033[1;31m[Enclave] Error: " + std::string(msg) + "\033[0m").c_str()); \
    else if (lvl == 1 && min_log_level <= 1) ocall_print_string(std::string("\033[1m[Enclave] Info:\033[0m " + std::string(msg)).c_str()); \
    else if (lvl == 0 && min_log_level <= 0) ocall_print_string(std::string("[Enclave] Debug: " + std::string(msg)).c_str()); \
    else if (lvl == -1 && min_log_level == -1) ocall_print_string(std::string("[Enclave] Trace: " + std::string(msg)).c_str()); \
    } while (0)

extern short min_log_level;

/**
 * @brief Structure for the SGX error table.
 */
typedef struct _sgx_errlist_t {
    sgx_status_t err;
    std::string msg;
    std::string sug;
} sgx_errlist_t;

/**
 * @brief Augmented structure used for extraction of the stack base and stack size values.
 * Original can be found under linug-sgx/common/inc/internal/thread_data.h
 */
typedef struct _thread_data_stripped_t {
    size_t  self_addr;
    size_t  last_sp;
    size_t  stack_base_addr;
    size_t  stack_limit_addr;
} thread_data_stripped_t;

/**
 * @brief Retrieves the stack base address using the aforementioned structure.
 * 
 * @return size_t stack base address
 */
size_t extract_stack_base();

/**
 * @brief Retrieves the stack size using the aforementioned structure.
 * 
 * @return size_t stack size
 */
size_t extract_stack_size();

/**
 * @brief For a given nonce, searches for a value that, when hashed using SHA256, renders a result 
 * with 'difficulty' leading zero bits.
 * 
 * @param nonce pointer to given nonce
 * @param result pointer to found value
 * @param difficulty number of leading zero bits the hashed value must have
 */
void calculate_pow(const uint32_t *nonce, uint32_t *result, int difficulty);

/**
 * @brief Sets the PoW flag of the worker to true and directly triggers the watcher PoW.
 * 
 * @param trigger_worker when true, also triggers the PoW for the worker thread
 * @param halt_worker when true, watcher halts current execution and starts hashing
 * @param watcher_nonce pointer to the nonce the current watcher must use for PoW
 * @param watcher_result pointer to the value found which respects the diffculty level
 */
void trigger_pow(bool trigger_worker, bool *halt_worker, uint32_t *watcher_nonce, uint32_t *watcher_result);

/**
 * @brief Prints an error in human-readable format based on an error code.
 * 
 * @param msg message to be printed alongside error
 * @param ret SGX error code
 */
void print_error_message(const std::string &msg, sgx_status_t ret);

/**
 * @brief Set up the log threshold.
 * 
 * @param level 0 = DEBUG, 1 = INFO, 2 = ERROR
 */
void setup_log_level(short level);


template<typename T>
class Buffer {

private:

    /**
     * @brief Pointer to wrapped buffer.
     */
    T *data_;

    /**
     * @brief Buffer size.
     */
    uint32_t size_;

    /**
     * @brief When true, the wrapper creates new buffer instead of housing an existing one.
     */
    bool internal = false;

public:

    /**
     * @brief Construct a new Buffer object by allocating memory w.r.t. to the given size.
     * 
     * @param s_arg size of buffer
     */
    explicit Buffer(uint32_t s_arg) {
        data_ = new T[s_arg];
        size_ = s_arg;
        internal = true;
    }

    /**
     * @brief Construct a new Buffer object as a wrapper for an already existing buffer.
     * 
     * @param d_arg pointer to existing buffer
     * @param s_arg size of buffer
     */
    Buffer(T *d_arg, uint32_t s_arg) {
        data_ = d_arg;
        size_ = s_arg;
    }

    /**
     * @brief When destroying the object, also release any memory, if allocated.
     */
    ~Buffer() {
        if (internal) delete[] data_;
    }

    /**
     * @brief Pointer to the wrapped buffer.
     * 
     * @return T* pointer of type T
     */
    T *data() const {
        return data_;
    }

    /**
     * @brief Size of wrapped buffer.
     * 
     * @return uint32_t size
     */
    [[nodiscard]] uint32_t size() const {
        return size_;
    }
};

/**
 * @brief This class provides the means to synchronize multiple watcher threads before starting the stack scanning of the worker thread.
 */
class Accumulator {

private:

    uint32_t acc_ = 0;

    uint32_t limit_ = 0;

    bool locked_ = false;

    sgx_thread_mutex_t mutex_ = SGX_THREAD_NONRECURSIVE_MUTEX_INITIALIZER;

    sgx_thread_mutexattr_t mutex_attr_ = {0};

    sgx_thread_cond_t cond_ = SGX_THREAD_COND_INITIALIZER;

public:

    /**
     * @brief Construct a new Accumulator object setting up the maximum number of threads that need to wait before the latch unlocks.
     */
    Accumulator() {
        sgx_thread_mutex_init(&mutex_, &mutex_attr_);
    }

    ~Accumulator() {
        sgx_thread_mutex_destroy(&mutex_);
    }

    void set_limit(uint32_t limit) {
        limit_ = limit;
    }

    /**
     * @brief If the limit has not been reached, wait until enough threads accumulate in order to continue further.
     */
    void wait() {
        sgx_thread_mutex_lock(&mutex_);

        if (!locked_ && acc_ == 0) {
            locked_ = true;
        }
        ++acc_;

        while (locked_ && acc_ < limit_) {
            sgx_thread_cond_wait(&cond_, &mutex_);
        }

        locked_ = false;
        --acc_;
        sgx_thread_cond_broadcast(&cond_);
        sgx_thread_mutex_unlock(&mutex_);
    }
};
