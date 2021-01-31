# DSV: Disassembly Soundness Validation
# Copyright (C) <2021> <Xiaoxin An> <Virginia Tech>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import argparse

from ..common import utils
from ..disassembler import helper

'''
$ python -m src.dsv_check.disassemble_in_batch -l benchmark/coreutils-build -d benchmark/coreutils-objdump -b 1
'''

INFIX = '.'

def disassemble_single(exec_path, disasm_dir, disasm_type='objdump'):
    file_name = utils.get_file_name(exec_path)
    new_path = os.path.join(disasm_dir, file_name + INFIX + disasm_type)
    utils.make_dir(os.path.dirname(new_path))
    helper.disassemble_to_asm(exec_path, new_path, disasm_type)


def disassemble_file_for_disassemblers(file_path):
    for disasm_type in ['objdump', 'angr', 'ghidra', 'bap', 'radare2', 'dyninst']:
        new_path = file_path + INFIX + disasm_type
        helper.disassemble_to_asm(file_path, new_path, disasm_type)


def disassemble_bin_files(files, disasm_dir, disasm_type='objdump'):
    for file_path in files:
        disassemble_single(file_path, disasm_dir, disasm_type)


if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Disassembly Soundness Verification')
    parser.add_argument('-t', '--disasm_type', default='objdump', type=str, help='Disassembler')
    parser.add_argument('-e', '--elf_dir', default='benchmark/coreutils-build', type=str, help='Benchmark folder name')
    parser.add_argument('-d', '--disasm_dir', default='litmus-test', type=str, help='Disassembled folder name')
    parser.add_argument('-f', '--file_name', type=str, help='Benchmark file name')
    parser.add_argument('-b', '--batch', default=1, type=int, help='Benchmark file name')
    args = parser.parse_args()
    if args.batch == 0:
        file_path = os.path.join(utils.PROJECT_DIR, os.path.join(args.lib, args.file_name))
        disasm_dir = os.path.join(utils.PROJECT_DIR, args.disasm_dir)
        disassemble_single(file_path, disasm_dir, args.disasm_type)    
    elif args.batch == 1:
        dir_path = os.path.join(utils.PROJECT_DIR, args.lib)
        disasm_dir = os.path.join(utils.PROJECT_DIR, args.disasm_dir)
        files = utils.get_executable_files(dir_path)
        for file_path in files:
            print(file_path.rsplit('/', 1)[1].strip())
        disassemble_bin_files(files, disasm_dir, args.disasm_type)
    elif args.batch == 2:
        file_path = os.path.join(utils.PROJECT_DIR, os.path.join(args.lib, args.file_name))
        disassemble_file_for_disassemblers(file_path)

