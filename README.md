# DSV: Disassembly Soundness Validation

DSV is a tool that automatically validates the soundness of a disassembly process.

Project structure:
DSV
|--benchmark
|   |--coreutils-build
|   |--coreutils-objdump
|   |--coreutils-radare2
|   |--coreutils-angr
|   |--coretuils-bap
|   |--coretuils-ghidra
|   |--coreutils-dyninst
|--litmus-test
|--micro-benchmark
|--src
|--lib
|   |--ghidra_9.0.4
|   |--disassemble_dyninst
|--LICENSE
|--README.md
|--test.s

Prerequisites:
    python3 (>= 3.7.1)
    objdump (>= 2.30)
    radare2 (3.7.1)
    angr (8.19.7.25)
    BAP (1.6.0)
    Ghidra (9.0.4)
    Dyninst(10.2.1)

Note:
    -- The compiled binary files for Coreutils are located at DSV/benchmark/coreutils-build
    -- The test cases used in Section 5.2 is stored in DSV/litmus-test
    -- A package of Ghidra and Dyninst has been stored in the DSV/lib directory


Apply DSV to construct a CFG on a specific file disasembled by a disassembler and get the information regarding # of instructions and unreachable instructions ...
$ python -m src.main -e benchmark/coreutils-build -l benchmark/coreutils-radare2 -t radare2 -f basename

Apply DSV to validate the soundness and report all the incorrectly disassembled instructions
$ python -m src.main -e benchmark/coreutils-build -l benchmark/coreutils-radare2 -t radare2 -f basename -s

Use DSV to build up the CFG for all the files under a directory
$ python -m src.main -e benchmark/coreutils-build -l benchmark/coreutils-radare2 -t radare2 -b

Use DSV to validate the soundness of all the files under a directory
$ python -m src.main -e benchmark/coreutils-build -l benchmark/coreutils-radare2 -t radare2 -b -s

Execute neat_unreach to detect whether an unreachable instruction is really black
$ python -m src.dsv_check.neat_unreach -e benchmark/coreutils-build -l benchmark/coreutils-radare2 -f basename -t radare2 -v

Compare the outputs from a disassembler with objdump to find the inconsistency
$ python -m src.dsv_check.disasm_diff -l benchmark/coreutils-radare2 -f basename -t radare2

