#include <iostream>
#include <string>
#include <boost/program_options.hpp>

#include "Decryptor.h"
#include "Utils/ProgressUtils.h"


namespace po = boost::program_options;

int main(int argc, char **argv) {
    std::string filesPath;
    std::string powFilePath;
    uint32_t powWorkerDiff;
    uint32_t powWatcherDiff;
    ProgressUtils progress;

    boost::program_options::arg = "VAL";
    po::options_description desc("Available options");
    desc.add_options()
            ("path", po::value<std::string>(), "Path to files used for decryption.")
            ("pow_path", po::value<std::string>(), "Path to file containing PoW challenges (in hex). "
                                                   "First line contains the Worker's challenge and all other lines contain the Watchers'.")
            ("pow_worker_difficulty", po::value<uint32_t>(), "Difficulty of the Worker's puzzle "
                                                             "(first <VAL> bits must be 0).")
            ("pow_watcher_difficulty", po::value<uint32_t>(), "Difficulty of the Watchers' puzzles "
                                                              "(first <VAL> bits must be 0).")
            ("reset_id", "Reset expected Payload ID to 0.")
            ("set_key_id", po::value<uint32_t>(), "Set expected Key ID to given number.")
            ("help", "Print this message.");

    po::variables_map map;
    po::store(po::parse_command_line(argc, argv, desc), map);
    po::notify(map);

    if (map.count("help")) {
        std::cout << desc << '\n';
        return 0;
    }

    if (map.count("path")) {
        filesPath = map["path"].as<std::string>();
        if (filesPath.back() != '/') {
            filesPath += '/';
        }
    } else {
        filesPath = "./";
        std::cout << ">> Using current path as target.\n";
    }

    if (map.count("pow_path")) {
        powFilePath = map["pow_path"].as<std::string>();
    } else {
        std::cerr << "No PoW challenge file provided! "
                     "This is necessary to verify the results received by the enclave threads.\n";
        exit(-1);
    }

    if (map.count("pow_worker_difficulty")) {
        powWorkerDiff = map["pow_worker_difficulty"].as<uint32_t>();
    } else {
        std::cerr << "No PoW difficulty specified for the Worker thread!\n";
        exit(-1);
    }

    if (map.count("pow_watcher_difficulty")) {
        powWatcherDiff = map["pow_watcher_difficulty"].as<uint32_t>();
    } else {
        std::cerr << "No PoW difficulty specified for the Watcher threads!\n";
        exit(-1);
    }

    if (map.count("reset_id")) {
        progress.writeFile({0, progress.get().keyId});
    }

    if (map.count("set_key_id")) {
        progress.writeFile({progress.get().id, map["set_key_id"].as<uint32_t>()});
    }

    progress.readFile();

    if (progress.get().id >= INT_MAX) {
        // If counter overflows, new symmetric key is necessary
        progress.writeFile({0, progress.get().keyId + 1});
    }

    Decryptor decryptor(filesPath, powFilePath, powWorkerDiff, powWatcherDiff, progress.get());
    decryptor.decrypt();

    progress.writeFile({progress.get().id + 1, progress.get().keyId});

    return 0;
}
