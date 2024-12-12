#include <cstring>

#include "StackCrawler.h"


StackCrawler::StackCrawler(size_t sb_arg, size_t ss_arg) : stack_base(sb_arg), stack_size(ss_arg) {
	// snap size = 4 (seed) + 2 * stack_size (hex representation) + stack_size / 4 (spaces) + stack_size / 16 (end-lines)
	snapshot_size = static_cast<uint32_t>(4 + 37 * stack_size / 16);
	snapshot = new char[snapshot_size];
	snapshot_hash = new uint8_t[SGX_SHA256_HASH_SIZE];
}

StackCrawler::~StackCrawler() {
	delete[] snapshot;
	delete[] snapshot_hash;
}

void StackCrawler::crawl(uint32_t seed) {
	// Insert the seed on the first 4 bytes
	std::memset(snapshot, 0, snapshot_size);
	*reinterpret_cast<uint32_t *>(snapshot) = seed;
	size_t glob_idx = 4;

	auto *start_addr = reinterpret_cast<unsigned char *>(stack_base - stack_size);
	char hex_group[9];

	for (size_t idx = 0; idx < stack_size; idx += 4) {
		// format output with spaces and newlines
		if (idx > 0) {
			snapshot[glob_idx++] = ' ';
		}
		if (idx % 16 == 0 && idx > 0) {
			snapshot[glob_idx++] = '\n';
		}

		std::snprintf(hex_group, 9, "%02x%02x%02x%02x",
					start_addr[idx + 3],
					start_addr[idx + 2],
					start_addr[idx + 1],
					start_addr[idx]);

		for (size_t jdx = 0; jdx < 8; jdx++) {
			snapshot[glob_idx++] = hex_group[jdx];
		}
	}

	if (SGX_SUCCESS != sgx_sha256_msg(reinterpret_cast<const uint8_t *>(snapshot), snapshot_size, 
		reinterpret_cast<sgx_sha256_hash_t *>(snapshot_hash))) {
		LOG(2, "Could not hash stack snapshot!");
	}
	// Delete traces of Watcher PoW solution
	*reinterpret_cast<uint32_t *>(snapshot) = 0;
	seed = 0;
}

unsigned char *StackCrawler::get_hash() const {
	return snapshot_hash;
}

const char *StackCrawler::dump() const {
    return const_cast<const char *>(snapshot + 4);
}

uint32_t StackCrawler::snapshot_length() const {
    return snapshot_size - 4;
}
