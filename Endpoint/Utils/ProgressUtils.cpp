/*
 *  Copyright (C) 2024 Fraunhofer AISEC
 *  Authors: Andrei-Cosmin Aprodu <andrei-cosmin.aprodu@aisec.fraunhofer.de>
 *
 *  ProgressUtils.cpp
 *
 *  Provides measurement functionalities for progress analysis.
 *
 *  All Rights Reserved.
 */


#include <string>
#include <fstream>

#include "ProgressUtils.h"


void ProgressUtils::writeFile(ProgressUtils::ProgressData pd) {
    progressData = pd;
    std::ofstream file(FILE_NAME, std::ios::binary | std::ios::trunc);

    file.write(reinterpret_cast<char *>(&pd), sizeof(pd));
    file.close();
}

void ProgressUtils::readFile() {
    std::ifstream file(FILE_NAME, std::ios::binary);
    ProgressData pd{};

    file.read(reinterpret_cast<char *>(&pd), sizeof(pd));
    progressData = pd;
    file.close();
}

ProgressUtils::ProgressData ProgressUtils::get() {
    return progressData;
}
