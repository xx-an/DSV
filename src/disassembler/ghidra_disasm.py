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
