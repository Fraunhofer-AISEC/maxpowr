#include <iostream>
#include <fstream>
#include <utility>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include "Decryptor.h"
#include "Utils/CryptoUtils.cpp"
#include "Utils/Buffer.h"


Decryptor::Decryptor(std::string path, std::string path2, uint32_t workerDiff, uint32_t watcherDiff,
                     ProgressUtils::ProgressData pd)
        : filesPath(std::move(path)), powFilePath(std::move(path2)), powWorkerDiff(workerDiff),
          powWatcherDiff(watcherDiff), progressData(pd) {}

void Decryptor::decrypt() {
    std::ifstream challengesIn(powFilePath);
    std::ifstream watcherIn(filesPath + std::to_string(progressData.keyId) + '_' + std::to_string(progressData.id)
                            + "_watcher.meta");
    std::ifstream workerIn(filesPath + std::to_string(progressData.keyId) + '_' + std::to_string(progressData.id)
                           + "_worker.meta");
    std::ifstream rsaIn(filesPath + std::to_string(progressData.keyId) + ".enc", std::ios::binary);
    std::ifstream macIvIn(filesPath + std::to_string(progressData.keyId) + '_' + std::to_string(progressData.id)
                          + ".maciv", std::ios::binary);
    std::ifstream aesIn(filesPath + std::to_string(progressData.keyId) + '_' + std::to_string(progressData.id)
                        + ".stackshot", std::ios::binary);

    if (challengesIn.fail() || watcherIn.fail() || workerIn.fail() || rsaIn.fail() || macIvIn.fail() || aesIn.fail()) {
        std::cerr << "One or more files required for decryption could not be opened!\n";
        exit(-1);
    }

    /* Verify PoW results */

    std::vector<std::string> watcherResults;
    std::vector<uint32_t> initialChallenges;
    std::vector<uint32_t> watcherFirstPowSolutions;
    std::vector<uint32_t> workerChallengeAndSolution;
    uint32_t lineCount = 0;

    std::vector<std::string> powChallengesData;
    boost::split(powChallengesData,
                 std::string(std::istreambuf_iterator<char>(challengesIn), std::istreambuf_iterator<char>()),
                 boost::is_any_of("\n"), boost::token_compress_on);
    for (const std::string &line: powChallengesData) {
        if (line.empty()) continue;
        std::vector<std::string> splitLine;
        boost::split(splitLine, line, boost::is_any_of(" "), boost::token_compress_on);
        initialChallenges.push_back(hexToInt(splitLine.at(0)));
        if (lineCount == 0) {
            workerChallengeAndSolution.push_back(hexToInt(splitLine.at(0)));
            workerChallengeAndSolution.push_back(hexToInt(splitLine.at(1)));
        } else {
            watcherFirstPowSolutions.push_back(hexToInt(splitLine.at(1)));
        }
        lineCount++;
    }

    std::vector<std::string> watcherData;
    boost::split(watcherData, std::string(std::istreambuf_iterator<char>(watcherIn), std::istreambuf_iterator<char>()),
                 boost::is_any_of("\n "), boost::token_compress_on);
    for (int i = 0; i < watcherData.size(); ++i) {
        if (watcherData.at(i).empty()) continue;
        if (i % 2 == 0) {
            if (std::find(initialChallenges.begin(), initialChallenges.end(), hexToInt(watcherData.at(i))) ==
                initialChallenges.end()) {
                std::cerr << "Found Watcher challenge which is not in '" << powFilePath << "', stopping!" << "\n";
                exit(-1);
            }
        } else {
            short startIndex = 0;
            if (!watcherData.at(i).rfind("0x", 0)) startIndex = 2;
            watcherResults.push_back(watcherData.at(i).substr(startIndex, watcherData.at(i).length() - startIndex));
        }
    }

    std::vector<std::string> workerData;
    boost::split(workerData, std::string(std::istreambuf_iterator<char>(workerIn), std::istreambuf_iterator<char>()),
                 boost::is_any_of("\n "), boost::token_compress_on);
    if (workerChallengeAndSolution.at(0) != hexToInt(workerData.at(0))) {
        std::cerr << "Found Worker challenge which is not in '" << powFilePath << "', stopping!" << "\n";
        exit(-1);
    }
    if (workerChallengeAndSolution.at(1) != hexToInt(workerData.at(1))) {
        std::cerr << "!!! Worker PoW returned an invalid result !!!\n";
        exit(-1);
    }

    /* Decrypt symmetric key */

    std::vector<byte> rsaPayload;
    rsaPayload.reserve(KeyMaterial::n_byte_size);
    std::copy(std::istreambuf_iterator<char>(rsaIn), std::istreambuf_iterator<char>(),
              std::back_inserter(rsaPayload));

    size_t plaintextLen = KeyMaterial::n_byte_size;
    Buffer<byte> plaintextRSA(KeyMaterial::n_byte_size);
    if (decryptRSA_SHA256(plaintextRSA.data(), &plaintextLen, static_cast<byte *>(&rsaPayload[0]),
                          KeyMaterial::n_byte_size)) {
        std::cerr << "Error decrypting symmetric key '" << std::to_string(progressData.keyId) + ".enc" << "'!\n";
        exit(-1);
    }

    /* Decrypt stack snapshot */

    std::vector<byte> macIvPayload;
    macIvPayload.reserve(AES_GCM_MAC_SIZE + AES_GCM_IV_SIZE);
    std::copy(std::istreambuf_iterator<char>(macIvIn), std::istreambuf_iterator<char>(),
              std::back_inserter(macIvPayload));

    std::vector<byte> aesPayload;
    std::copy(std::istreambuf_iterator<char>(aesIn), std::istreambuf_iterator<char>(),
              std::back_inserter(aesPayload));

    Buffer<uint8_t> symmetricKey(plaintextRSA.data(), AES_GCM_KEY_SIZE);
    Buffer<uint8_t> ciphertextAES(&aesPayload[0], aesPayload.size() - AES_GCM_MAC_SIZE - AES_GCM_IV_SIZE);
    Buffer<uint8_t> plaintextAES(ciphertextAES.size());
    Buffer<uint8_t> iv(&macIvPayload[AES_GCM_MAC_SIZE], AES_GCM_IV_SIZE);
    Buffer<uint8_t> aad(reinterpret_cast<uint8_t *>(&progressData.id), sizeof(progressData.id));
    Buffer<uint8_t> mac(&macIvPayload[0], AES_GCM_MAC_SIZE);

    if (decryptAES128GCM(reinterpret_cast<aes_gcm_128bit_t *>(symmetricKey.data()),
                         ciphertextAES.data(), ciphertextAES.size(),
                         plaintextAES.data(),
                         iv.data(), iv.size(),
                         aad.data(), aad.size(),
                         reinterpret_cast<aes_gcm_128bit_t *>(mac.data()))) {
        std::cerr << "Error decrypting stack snapshot '"
                  << std::to_string(progressData.keyId) + '_' + std::to_string(progressData.id) +
                     ".stackshot" << "'!\n";
        std::cerr << "Tried with: Key ID = " << progressData.keyId << ", Payload ID = " << progressData.id << '\n';
        exit(-1);
    }

    /* Verify second Watcher PoW */

    bool hashMatchFound = false;
    for (auto &powSolution: watcherFirstPowSolutions) {
        byte snapshotHashRaw[SHA256_HASH_SIZE];
        byte snapshot[plaintextAES.size() + 4];
        *reinterpret_cast<uint32_t *>(snapshot) = powSolution;
        std::memcpy(snapshot + 4, plaintextAES.data(), plaintextAES.size());

        if (generateSHA256(snapshot, plaintextAES.size() + 4, snapshotHashRaw)) {
            std::cerr << "Error generating snapshot hash for "
                      << std::to_string(progressData.keyId) + '_' + std::to_string(progressData.id) + ".stackshot"
                      << "'!\n";
            exit(-1);
        }

        uint32_t powSolution2Raw = calculatePowSolution(*reinterpret_cast<uint32_t *>(snapshotHashRaw), powWatcherDiff);
        std::stringstream ss;
        ss << std::setw(8) << std::setfill('0') << std::hex << powSolution2Raw;
        std::string powSolution2 = ss.str();

        if (watcherResults.end() != std::find(watcherResults.begin(), watcherResults.end(), powSolution2)) {
            hashMatchFound = true;
            break;
        }
    }
    if (!hashMatchFound) {
        std::cerr << "!!! Snapshot hash for "
                  << std::to_string(progressData.keyId) + '_' + std::to_string(progressData.id) + ".stackshot"
                  << "' does not correspond with any of the received signatures !!!\n";
        exit(-1);
    }

    /* Output snapshot files */

    std::ofstream stackshotOut(std::to_string(progressData.keyId) + '_' + std::to_string(progressData.id)
                               + ".stackshot.txt", std::ios::trunc);
    stackshotOut << plaintextAES.data();
    stackshotOut.close();
    std::cout << ">> Decrypted \"" << progressData.keyId << '_' << progressData.id << ".stackshot\" > \""
              << progressData.keyId << '_' << progressData.id << ".stackshot.txt\".\n";

    watcherIn.close();
    workerIn.close();
    rsaIn.close();
    macIvIn.close();
    aesIn.close();
}

uint32_t Decryptor::hexToInt(const std::string &hex) {
    short startIndex = 0;
    if (!hex.rfind("0x", 0)) {
        startIndex = 2;
    }

    uint32_t result = 0;
    std::stringstream ss;
    ss << std::hex << hex.substr(startIndex, hex.length() - startIndex);
    ss >> result;
    return result;
}

uint32_t Decryptor::calculatePowSolution(uint32_t challenge, uint32_t difficulty) {
    uint8_t digest[32] = {0};
    uint8_t seed[8];
    std::memset(seed, 0, 8);
    *reinterpret_cast<uint32_t *>(seed) = challenge;

    for (uint32_t i = 0; i < 0xffffffff; ++i) {
        *reinterpret_cast<uint32_t *>(seed + 4) = i;
        int hashDifficulty = difficulty;

        if (generateSHA256(seed, 8, digest)) {
            std::cerr << "Error during proof-of-work computation!\n";
            exit(-1);
        }

        bool correctSeed = true;
        uint32_t hashIndex = 0;
        while (hashDifficulty >= 8) {
            if (digest[hashIndex++] != 0) {
                correctSeed = false;
                break;
            }
            hashDifficulty -= 8;
        }
        if (correctSeed && hashDifficulty > 0 && digest[hashIndex] >> (8 - hashDifficulty) != 0) {
            continue;
        }
        if (correctSeed) {
            return i;
        }
    }
    return -1;
}
