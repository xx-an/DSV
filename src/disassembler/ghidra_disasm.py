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

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import AddressSet

GHIDRA_BASE = 0x100000
# addset = AddressSet()
# addset.add(currentAddress)
# print(currentProgram.getLanguage().getProcessor())
# print(currentAddress)
# cmd = DisassembleCommand(addset, None, True)
# cmd.applyTo(currentProgram, ConsoleTaskMonitor())
# res = cmd.getDisassembledAddressSet()
# activeAddr = currentLocation.getByteAddress()
# print(activeAddr)
# print(res)
currentProgram.setImageBase(currentAddress.subtract(GHIDRA_BASE), True)
execMemSet = currentProgram.getMemory()
instIter = currentProgram.getListing().getInstructions(execMemSet, True)
result = ''
while instIter.hasNext():
    inst = instIter.next()
    result += inst.getAddress().toString()
    result += '(' + str(len(inst.getBytes())) + '): '
    result += inst.toString() + '\n'
print('--- instructions ---')
print(result)
print('--- instructions ---')
