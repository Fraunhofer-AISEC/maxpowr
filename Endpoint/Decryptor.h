#pragma once

#include <string>

#include "Utils/ProgressUtils.h"


class Decryptor {

private:

    /**
     * @brief Path to the files used in the decryption process.
     */
    std::string filesPath;

    /**
     * @brief Path to the file containing proof-of-work challenges for all threads running inside the enclave.
     * The first one is reserved for the worker thread. The following ones belong to the watchers.
     * All challenges must be written in hexadecimal format.
     */
    std::string powFilePath;

    /**
     * @brief Difficulty of the Worker's cryptographic puzzle. It represents the number of leading zero bits the
     * SHA256 digest must have.
     */
    uint32_t powWorkerDiff;

    /**
     * @brief Difficulty of the Watchers' cryptographic puzzles. It represents the number of leading zero bits the
     * SHA256 digest must have.
     */
    uint32_t powWatcherDiff;

    /**
     * @brief Variable containing the current Payload ID (AAD used by the symmetric cipher) and the Key ID.
     */
    ProgressUtils::ProgressData progressData;

    /**
     * @brief Transforms a hex string into a 32 bit integer.
     */
    static uint32_t hexToInt(const std::string &hex);

    /**
     * @brief Calculates a PoW puzzle given "challenge" as seed and "difficulty" as PoW difficulty. This means
     * that the final SHA256 digest must start with "difficulty" leading zero bits.
     * 
     * Note: In a real-life scenario, we already know which result to expect from the enclave, so recalculating
     * the PoW will not be necessary. However, in this proof-of-concept we choose this approach for simplicity.
     */
    static uint32_t calculatePowSolution(uint32_t challenge, uint32_t difficulty);

public:

    Decryptor(std::string path, std::string path2, uint32_t workerDiff, uint32_t watcherDiff,
              ProgressUtils::ProgressData pd);

    ~Decryptor() = default;

    /**
     * @brief Run the entire decryption pipeline and, after a successful run, write the results to a text file.
     */
    void decrypt();
};
