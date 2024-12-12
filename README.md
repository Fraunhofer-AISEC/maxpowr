# Information

This is a repository which contains a proof-of-concept implementation for the published paper called "MAXPoWR: Memory Attestation and Export in Process-based Trusted Execution Environments" published 2024 in the 23rd IEEE International Conference on Trust, Security and Privacy in Computing and Communications (TrustCom-2024).

This project is not maintained. Note that this repository presents a prototype implementation and is not to be used in production.

# Stack Snapshot Exporter for Intel SGX


## Introduction
[Intel Software Guard Extensions (SGX)](https://github.com/intel/linux-sgx) is a technology built to protect code and data from disclosure and modification by housing them in trusted execution environments (TEEs) called *enclaves*. Since information residing inside a TEE is not accessible from the outside, other untrusted executables are not allowed to monitor the shielded process. As a result, the process itself must offer this information.

This project builds an SGX enclave comprised of multiple parallel threads. One of them is the *Worker* thread and the others are *Watchdogs* (or *Watchers*) which scan the entire stack of the Worker, then send the encrypted snapshots to a remote Endpoint. The current model assumes that the Worker might present vulnerabilities. Runtime attestation can help in preventing these vulnerabilities from being exploited by identifying ongoing attacks based on the received stack snapshots.  

There are **2** main directories:
* [The Enclave Memory Exporter](./MemExporter/README.md)
* [The Endpoint (Decryptor)](./Endpoint/README.md)


## Requirements

The following list contains all requirements from the aforementioned projects:
* C++17
* Python 3.7 or later
* [Intel SGX for Linux](https://github.com/intel/linux-sgx)
* [CMake](https://cmake.org/) 3.16 or later
* [OpenSSL](https://www.openssl.org/)
* [Boost.Program_options](https://www.boost.org/doc/libs/1_63_0/doc/html/program_options.html) 1.36.0 or later

```shell
apt install python3 cmake libssl-dev libboost-program-options-dev
```

**NOTE:** The project was tested on *Ubuntu 20.04* with *Intel SGX 2.15.1*.


## Quick Start

This section provides the necessary steps to extract an encrypted stack snapshot from the enclave and decrypt it at the Endpoint. As the actual networking pipeline for sending the files is *not provided*, we will run all programs on the same machine.

### Build Everything

Go to the root of this project, then run:

```shell
cd MemExporter && make && cd ..
cd Endpoint && cmake . && make && cd ..
```

### Run the Demo

1. First, start by generating snapshots of the enclave's stack:

   ```shell
   cd MemExporter/Build && ./app && cd ../..
   ```

    *Output:*
   ```
   [Enclave] Info: Running dummy task...
   [Enclave] Info: Generated "1_0.stackshot".
   [Enclave] Info: Generated "1_1.stackshot".
   [Enclave] Info: Generated "1_2.stackshot".
   [Enclave] Info: Generated "1_3.stackshot".
   [Enclave] Info: Dummy task finished!
   [Outside] Info: Successfully returned.
   ```
   Every message logged by the Memory Exporter starts with one of the following tags: 
   * `[Enclave]` = messages are printed by the *enclave* itself,
   * `[Outside]` = messages are printed by the *untrusted codebase*.

2. All output files are stored in `MemExporter/SnapshotData`. We will use this directory as source for our Endpoint:

   ```shell
   cd Endpoint
   for _ in {0..3}; do ./endpoint --path ../MemExporter/SnapshotData/ --pow_path ./powChallenges.txt --pow_watcher_difficulty 8 --pow_worker_difficulty 24; done
   ```
    
   *Output:*
   ```
   >> Decrypted "1_0.stackshot" > "1_0.stackshot.txt".
   >> Decrypted "1_1.stackshot" > "1_1.stackshot.txt".
   >> Decrypted "1_2.stackshot" > "1_2.stackshot.txt".
   >> Decrypted "1_3.stackshot" > "1_3.stackshot.txt".
   ```
   Each command decrypts *one payload* and prepares for the next. Since the enclave defaults to generating 4 snapshots, we call the Endpoint 4 times to decrypt everything. For more details, please refer to the Endpoint's [README.md](./Endpoint/README.md). All decrypted stack snapshots are stored in files terminating in `.stackshot.txt`. These plaintext files can be found in the directory where the Endpoint binary resides.


## Build Options

In `MemExporter/buildenv.mk`, one can find build settings for this project. Amongst these, there are `INJECTOR_PAYLOAD` and `INJECTOR_TARGET`. At compile time, the Python script `MemExporter/Injector/Injector.py` scans the Worker's logic and injects after each C++ command a macro which enables pausing the execution everytime the attestation process starts. The path to the file where the macro resides is given by the attribute `INJECTOR_PAYLOAD`. The path to the Worker's source file to be parsed is given by the attribute `INJECTOR_TARGET`. Here, the file extension is *left out* on purpose, since the script assumes the header and source files to have the same base name.

Since this project is a proof of concept, the necessary networking for transmitting the encrypted packets from the enclave to the remote endpoint was *not provided*. In a real-world scenario, the enclave would run indefinitely, until instructed otherwise by that endpoint. To compensate for the lack of communication, we have set up the enclave to perform a finite number of scans *(default is 5)*, then stop. The number of runs is stored by the integer `run_cycles` found in `MemExporter/App/App.cpp`.
