 #
 #  Copyright (C) 2024 Fraunhofer AISEC
 #  Authors: Andrei-Cosmin Aprodu <andrei-cosmin.aprodu@aisec.fraunhofer.de>
 #
 #  Injector.py
 #
 #  Applies the macro of InjectedMacro.hpp into source code.
 #
 #  All Rights Reserved.
 #

import sys
import os
import re

from argparse import ArgumentParser
from pathlib import Path


def inject_halting_code(hdr_file_name: str, hdr_ext: str, hdr_code: list, src_code: list, payload: list):
    macro_name = ""
    modded_hdr_code = [f"/**\n * \"_gen\" file generated automatically, DO NOT modify!"
                       f"\n * To add changes, edit its source: {hdr_file_name}.h\n */\n"]
    modded_hdr_code.extend(hdr_code)
    modded_hdr_code.append("\n")

    for line in payload:
        if len(line.strip()) == 0 or line.strip().startswith("//"):
            continue
        modded_hdr_code.append(line)
        if line.startswith("#define"):
            macro_name = line.split()[1] if "(" not in line.split()[1] \
                else re.split("[( ]", line)[1] + "(" + re.split("[()]", line)[1] + ")"

    modded_src_code = [f"/**\n * \"_gen\" file generated automatically, DO NOT modify!"
                       f"\n * To add changes, edit its source: {hdr_file_name}.cpp\n */\n"]

    for line in src_code:
        if "#include" in line.strip() and (hdr_file_name + "." + hdr_ext) in line.strip():
            modded_src_code.append("#include \"" + hdr_file_name + "_gen." + hdr_ext + "\"\n")
        else:
            modded_src_code.append(line)
        if len(line.strip()) > 0 and (line.strip()[-1] == ";" or line.strip()[-1] == "{"):
            modded_src_code.append(macro_name + ";\n")

    return modded_hdr_code, modded_src_code


def main():
    usage = "Inject halting points into the Worker's code such that it can be stopped by the Watcher threads."
    parser = ArgumentParser(usage=usage)
    parser.add_argument("--header", type=str, help="path to target header file (e.g. .h)", required=True)
    parser.add_argument("--source", type=str, help="path to target source file (e.g. .cpp)", required=True)
    parser.add_argument("--payload", type=str, help="path to file containing the macro to be injected", required=True)

    args = parser.parse_args()
    src_file_path = args.source
    hdr_file_path = args.header
    payload_file_path = args.payload

    if not Path(src_file_path).is_file() or not Path(hdr_file_path).is_file() or not Path(payload_file_path).is_file():
        print("One or more given files could not be found!", file=sys.stderr)
        exit(-1)

    src_dir_path, file = os.path.split(src_file_path)
    if "/" in src_file_path:
        src_dir_path += "/"
    src_file_name, _, src_ext = file.rpartition(".")

    hdr_dir_path, file = os.path.split(hdr_file_path)
    if "/" in hdr_file_path:
        hdr_dir_path += "/"
    hdr_file_name, _, hdr_ext = file.rpartition(".")

    with open(src_file_path, 'r') as src_file, \
            open(hdr_file_path, 'r') as hdr_file, \
            open(payload_file_path, 'r') as payload_file:
        modded_hdr_code, modded_src_code = inject_halting_code(hdr_file_name, hdr_ext, hdr_file.readlines(),
                                                               src_file.readlines(), payload_file.readlines())

    with open(hdr_dir_path + hdr_file_name + "_gen." + hdr_ext, "w") as modded_hdr_file:
        modded_hdr_file.writelines(modded_hdr_code)

    with open(src_dir_path + src_file_name + "_gen." + src_ext, "w") as modded_src_file:
        modded_src_file.writelines(modded_src_code)


if __name__ == '__main__':
    main()
