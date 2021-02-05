#include <iostream>
#include <boost/make_shared.hpp>
#include "CodeObject.h"
#include "InstructionDecoder.h"
using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

int main(int argc, char **argv) {
    if(argc != 2) {
        printf("Usage: %s <binary path>\n", argv[0]);
        return -1;
    }
    char *binaryPath = argv[1];
    
    SymtabCodeSource *sts;
    CodeObject *co;
    Instruction::Ptr instr;
    SymtabAPI::Symtab *symTab;
    std::string binaryPathStr(binaryPath);
    bool isParsable = SymtabAPI::Symtab::openFile(symTab, binaryPathStr);
    if(isParsable == false) {
        const char *error = "error: file cannot be parsed";
        cout << error;
        return -1;
    }
    sts = new SymtabCodeSource(binaryPath);
    co = new CodeObject(sts);
    //parse the binary given as a command line arg
    co->parse();
    
    const map<Address, string> & lm = co->cs()->linkage();
    map<Address, string>::const_iterator lit = lm.begin();
    std::set<CodeRegion*> regs;
    co->cs()->findRegions(lit->first, regs);
    if (regs.size() == 1) {
        CodeRegion *reg = *regs.begin();
        const unsigned char* bufferBegin = 
            (const unsigned char *)(co->cs()->getPtrToInstruction(lit->first));
        InstructionDecoder decoder = InstructionDecoder(bufferBegin,
            InstructionDecoder::maxInstructionLength, Arch_x86_64);
        for( ; lit != lm.end(); ++lit) {
            cout << "\n\"" << lit->second.c_str() << "@plt\" :";
            Address crtAddr = lit->first;
            int i = 0;
            while(i < 2){
                instr = boost::make_shared<Instruction>(decoder.decode((unsigned char *)co->cs()->getPtrToInstruction(crtAddr)));
                    cout << "\n" << hex << crtAddr;
                    cout << "(" << instr->size();
                    cout << "): " << instr->format();
                crtAddr += instr->size();
                i += 1;
            }
            cout << "\n";
        }
    }

    SymtabAPI::Region * plt_got = NULL;
    if (symTab->findRegion(plt_got, ".plt.got")) {
        const unsigned char* buffer = (const unsigned char*)plt_got->getPtrToRawData(); 
        InstructionDecoder decoder = InstructionDecoder(buffer, plt_got->getMemSize(), Arch_x86_64);
        cout << "\n\"" << plt_got->getRegionName() << "\" :";
        int decoded = 0;
        while (decoded < plt_got->getMemSize()) {
        InstructionAPI::Instruction inst = decoder.decode();
        cout << "\n" << hex << plt_got->getMemOffset() + decoded;
            cout << "(" << inst.size();
            cout << "): " << inst.format();
        decoded += inst.size();
        }
        cout << "\n";
    }

    //get list of all functions in the binary
    const CodeObject::funclist &all = co->funcs();
    if(all.size() == 0){
        const char *error = "error: no functions in file";
        cout << error;
        return -1;
    }
    auto fit = all.begin();
    Function *f = *fit;
    //create an Instruction decoder which will convert the binary opcodes to strings
    InstructionDecoder decoder = InstructionDecoder(f->isrc()->getPtrToInstruction(f->addr()),
        InstructionDecoder::maxInstructionLength, Arch_x86_64);
    for(;fit != all.end(); ++fit){
        Function *f = *fit;
        //get address of entry point for current function
        Address crtAddr = f->addr();
        instr = boost::make_shared<Instruction>(decoder.decode((unsigned char *)f->isrc()->getPtrToInstruction(crtAddr)));
        auto fbl = f->blocks().end();
        fbl--;
        Block *b = *fbl;
        Address lastAddr = b->last();
        //if current function has zero instructions, d o n t output it
        if(crtAddr == lastAddr) continue;
        cout << "\n\"" << f->name() << "\" :";
        while(crtAddr <= lastAddr){
            //decode current instruction
            instr = boost::make_shared<Instruction>(decoder.decode((unsigned char *)f->isrc()->getPtrToInstruction(crtAddr)));
            cout << "\n" << hex << crtAddr;
            cout << "(" << instr->size();
            cout << "): " << instr->format();
            //go to the address of the next instruction
            crtAddr += instr->size();
        }
        cout << "\n";
    }
    cout << "\n";
    return 0;
}
