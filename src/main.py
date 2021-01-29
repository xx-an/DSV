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
import time
import xlwt
import argparse
import logging
from .common import utils
from .common import global_var
from .disassembler import helper
from .disassembler.disasm_factory import Disasm_Factory
from .cfg.cfg import CFG
from .soundness import soundness
from .dsv_check import neat_unreach


CHECK_RESULTS = ['', '$\\times$']

def construct_cfg(exec_path, disasm_asm, disasm_type):
    start_address = global_var.elf_info.entry_address
    main_address = global_var.elf_info.main_address
    address_sym_table = global_var.elf_info.address_sym_table
    sym_table = global_var.elf_info.sym_table
    cfg = CFG(sym_table, address_sym_table, disasm_asm.address_inst_map, disasm_asm.address_next_map, start_address, main_address, disasm_type)
    return cfg


def set_logger(disasm_path, disasm_type, verbose=False):
    for log_name in utils.LOG_NAMES:
        logger_path = disasm_path.replace('.' + disasm_type, '.' + log_name)
        utils.setup_logger(log_name, logger_path, verbose)

def close_logger():
    for log_name in utils.LOG_NAMES:
        utils.close_logger(log_name)


def write_results(disasm_asm, cfg, exec_time):
    reachable_address_num = len(cfg.reachable_addresses())
    indirects_num = len(cfg.indirect_inst_set)
    utils.logger.info(disasm_asm.valid_address_no)
    utils.logger.info(reachable_address_num)
    utils.logger.info(indirects_num)
    utils.logger.info(exec_time)


def check_soundness(elf_lib_dir, disasm_lib_dir, disasm_type, file_name):
    disasm_log_path = os.path.join(disasm_lib_dir, file_name + '.log')
    exec_path = os.path.join(elf_lib_dir, file_name)
    global_var.get_elf_info(exec_path)
    res = soundness.sound_disasm_file(global_var.elf_content, disasm_log_path)
    return res


def check_soundness_batch(elf_lib_dir, disasm_lib_dir, disasm_type):
    disasm_log_files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(disasm_lib_dir) for f in filenames if f.endswith('.log')]
    for disasm_log_path in disasm_log_files:
        file_name = utils.get_file_name(disasm_log_path)
        exec_path = os.path.join(elf_lib_dir, file_name)
        print(file_name)
        global_var.get_elf_info(exec_path)
        soundness.sound_disasm_file(global_var.elf_content, disasm_log_path)
        time.sleep(30)
        

def dsv_main(exec_path, disasm_path, disasm_type, verbose=False):
    set_logger(disasm_path, disasm_type, verbose)
    global_var.get_elf_info(exec_path)
    helper.disassemble_to_asm(exec_path, disasm_path, disasm_type)
    disasm_factory = Disasm_Factory(disasm_path, exec_path, disasm_type)
    disasm_asm = disasm_factory.get_disasm()
    start_time = time.time()
    cfg = construct_cfg(exec_path, disasm_asm, disasm_type)
    exec_time = time.time() - start_time
    write_results(disasm_asm, cfg, exec_time)
    close_logger()


def dsv_batch(elf_lib_dir, disasm_lib_dir, disasm_type, verbose=False):
    disasm_files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(disasm_lib_dir) for f in filenames if f.endswith(disasm_type)]
    for disasm_path in disasm_files:
        file_name = utils.get_file_name(disasm_path)
        exec_path = os.path.join(elf_lib_dir, file_name)
        try:
            print(file_name)
            dsv_main(exec_path, disasm_path, disasm_type, verbose)
            time.sleep(30)
        except:
            close_logger()
            time.sleep(60)
            continue


def dsv_specified(file_names, elf_lib_dir, disasm_lib_dir, disasm_type, verbose=False):
    for file_name in file_names:
        exec_path = os.path.join(elf_lib_dir, file_name)
        disasm_path = os.path.join(disasm_lib_dir, file_name + '.' + disasm_type)
        try:
            dsv_main(exec_path, disasm_path, disasm_type, verbose)
            time.sleep(30)
            para_list = neat_unreach.main_single(file_name, elf_lib_dir, disasm_lib_dir, disasm_type, False)
            res = check_soundness(elf_lib_dir, disasm_lib_dir, disasm_type, file_name)
            check_result = CHECK_RESULTS[0] if res else CHECK_RESULTS[1]
            print(' & ' + file_name + ' & ' + ' & '.join(list(map(lambda x: str(x), para_list))) + ' & ' + check_result + ' \\\\')
        except:
            close_logger()
            time.sleep(60)
            continue


if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Disassembly Soundness Verification')
    parser.add_argument('-t', '--disasm_type', default='objdump', type=str, help='Disassembler')
    parser.add_argument('-b', '--batch', default=0, type=int, help='Run dsv_main in batch mode') 
    parser.add_argument('-s', '--soundness', default=False, action='store_true', help='Check the soundness for specific file') 
    parser.add_argument('-l', '--log_path', default='benchmark/coreutils-objdump', type=str, help='Benchmark library') 
    parser.add_argument('-e', '--elf_path', default='benchmark/coreutils-build', type=str, help='Elf shared object library') 
    parser.add_argument('-f', '--file_name', type=str, help='Benchmark file name')
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help='Whether to print log information on the screen')
    args = parser.parse_args()
    disasm_type = args.disasm_type
    disasm_lib_dir = os.path.join(utils.PROJECT_DIR, args.log_path)
    elf_lib_dir = os.path.join(utils.PROJECT_DIR, args.elf_path)
    if args.soundness:
        if args.batch == 0:
            check_soundness(elf_lib_dir, disasm_lib_dir, disasm_type, args.file_name)
        else:
            check_soundness_batch(elf_lib_dir, disasm_lib_dir, disasm_type)    
    else:
        if args.batch == 0:
            disasm_path = os.path.join(disasm_lib_dir, args.file_name + '.' + disasm_type)
            exec_path = os.path.join(elf_lib_dir, args.file_name)
            dsv_main(exec_path, disasm_path, disasm_type, args.verbose)
        elif args.batch == 1:
            dsv_batch(elf_lib_dir, disasm_lib_dir, disasm_type, args.verbose)
        else:
            file_names = ['basename', 'expand', 'link', 'mknod', 'uname', 'realpath', 'comm', 'echo']
            dsv_specified(file_names, elf_lib_dir, disasm_lib_dir, disasm_type, args.verbose)
            
    
    
    
        