/*
 *  Copyright (C) 2024 Fraunhofer AISEC
 *  Authors: Andrei-Cosmin Aprodu <andrei-cosmin.aprodu@aisec.fraunhofer.de>
 *
 *  ProgressUtils.h
 *
 *  Provides measurement functionalities for progress analysis.
 *
 *  All Rights Reserved.
 */

#pragma once

#include <string>

#define FILE_NAME "progress.ckpt"


/**
 * @brief Class which creates a checkpoint file that stores the expected Payload ID and Key ID.
 */
class ProgressUtils {

public:

    /**
     * @brief Underlying data structure. After each run, the Payload ID is expected to increment by 1, whereas the
     * Key ID is expected to remain unchanged as long as the Payload ID does not overflow.
     */
    struct ProgressData {
        uint32_t id = 0;
        uint32_t keyId = 1;
    };

private:

    /**
     * @brief Variable to store the two integers.
     */
    ProgressData progressData;

public:

    ProgressUtils() = default;

    ~ProgressUtils() = default;

    /**
     * @brief Creates a checkpoint file with the name 'progress.ckpt', or overwrites an already existing one.
     * @param pd data to be stored in the file
     */
    void writeFile(ProgressData pd);

    /**
     * @brief Reads a 'progress.ckpt' and stores the data in memory.
     */
    void readFile();

    /**
     * @brief Returns the contents of the checkpoint file.
     * @return value containing the two integers
     */
    ProgressData get();
};
