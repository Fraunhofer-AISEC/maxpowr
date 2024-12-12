#pragma once


#include "EnclaveSGXUtils.h"
#include "sgx_trts.h"


class StackCrawler {

private:
	/**
	 * @brief Type used by the SGX SDK.
	 */
	typedef long unsigned int size_t;

	/**
	 * @brief Array which stores the stack snapshot of the worker thread.
	 */
	char *snapshot;

	/**
	 * @brief Array of bytes containing the resulting SHA256 hash of the stack snapshot.
	 */
	uint8_t *snapshot_hash;

	/**
	 * @brief Size of the stack snapshot.
	 */
	uint32_t snapshot_size;

	/**
	 * @brief Stack base address.
	 */
	size_t stack_base;

	/**
	 * @brief Stack size.
	 */
	size_t stack_size;

public:
	StackCrawler(size_t sb_arg, size_t ss_arg);

	~StackCrawler();

	/**
	 * @brief Given the worker's stack boundaries, scans it entire stack and stores the formatted
	 * information into an array. At the end, it produces a signature of the snapshot using SHA256.
	 * 
	 * @param seed uint32_t result of the watcher's PoW which is included in the snapshot hash
	 */
    void crawl(uint32_t seed);

	/**
	 * @brief Returns a hash of the stack calculated by 'crawl()'.
	 * 
	 * @return unsigned char* hash of the stack snapshot including the nonce
	 */
	[[nodiscard]] unsigned char *get_hash() const;

    /**
     * @brief Returns a snapshot of the stack obtained by 'crawl()'.
     * 
     * @return const char* pointer to the snapshot
     */
    [[nodiscard]] const char *dump() const;

    /**
     * @brief Returns the length of the stack snapshot.
     * 
     * @return uint32_t length
     */
    [[nodiscard]] uint32_t snapshot_length() const;
};
