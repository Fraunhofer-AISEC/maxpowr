# Endpoint (Decryptor)

The Endpoint is responsible with validating and decrypting the payload received from the enclave. As input, it must be provided with the appropriate `.meta`, `.enc`, `.maciv` and `.stackshot` files. After a successful validation, it saves the decrypted stack snapshot to a `.stackshot.txt` file.

Before decrypting, the Endpoint verifies that the received solutions for the proof-of-work challenges are valid and that the hashes of the stack snapshot match the received payload. The proof-of-work information resides in the `powChallenges.txt` file, where the **first line** is always reserved for the **Worker** and contains its given challenge, followed by the expected solution. The **following lines** are dedicated to the **Watchers** and contain pairs of one challenge and the solution. Because the Watcher PoWs are fed as seeds for the stack hashes, they are not included in the packages sent to the Endpoint. As a result, the input file of the Endpoint must be the one providing this data. For more details on the hashing process, please refer to the [README.md](../MemExporter/README.md) of the *Memory Exporter*. In a real-life scenario, the aforementioned packages will be sent to the enclave at the beginning of the attestation process in a so-called *attestation request*, but since this project is a proof-of-concept, we hard-code the same challenges into the enclave's source code.

Since every snapshot is shipped with a different ID as *associated data* and symmetric keys might also be refreshed (in case of integer overflow), the Endpoint saves all this information to a *checkpoint file* `progress.ckpt` after each run. This allows the program to always check for the appropriate key and payload IDs without the need for additional user input.


## Requirements
* C++17
* [CMake](https://cmake.org/) 3.16 or later
  ```shell
  apt install cmake
  ```
* [OpenSSL](https://www.openssl.org/)
  ```shell
  apt install libssl-dev
  ```
* [Boost.Program_options](https://www.boost.org/doc/libs/1_63_0/doc/html/program_options.html) 1.36.0 or later
  ```shell
  apt install libboost-program-options-dev
  ```


## Build

In the root directory `Endpoint`, execute:
```shell
cmake . && make
```


## Run

The executable can be called with the following arguments:
```shell
./endpoint [--help] [--reset_id] [--set_key_id <new_id>] [--path <file>] [--pow_path <file>]
           [--pow_watcher_difficulty <int>] [--pow_worker_difficulty <int>]
```
**Required arguments:**
* `--pow_path` sets with `<file>` the location of the PoW challenges source. The first line is always the Worker's challenge
* `--pow_watcher_difficulty` defines with `<int>` the number of leading zero bits the SHA256 digest of a Watcher's challenge and solution must have
* `--pow_worker_difficulty` defines with `<int>` the number of leading zero bits the SHA256 digest of the Worker's challenge and solution must have

**Optional arguments:**
* `--help` prints a help prompt
* `--reset_id` resets the expected Payload ID (associated data) to 0
* `--set_key_id` resets with `<new_id>` the expected Key ID
* `--path` sets with `<file>` the location of the files used for decryption. Defaults to current directory
