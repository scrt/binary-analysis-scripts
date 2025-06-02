#!/use/bin/python3
import argparse
from pathlib import Path
import re
import base64
import zlib
import json
from typing import List, Union, Tuple, TYPE_CHECKING


#from ghidra.util.task import ConsoleTaskMonitor
import pyhidra
#print("pyhidra")
pyhidra.start(False)
#print("pyhidra")

# needed for ghidra python vscode autocomplete
if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *

# Java imports
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function


def getString(addr):
    mem = currentProgram.getMemory()
    core_name_str = ""
    try:
        while True:
            byte = mem.getByte(addr.add(len(core_name_str)))
            if byte == 0:
                return core_name_str
            core_name_str += chr(byte)
    except:
        #print("Error getting string")
        return ""

def doOutput(data,output_file):
    print("{} : \033[92m[+] {}\033[0m is called from \033[92m{}\033[0m at 0x{} with interesting value : \033[92m{}\033[0m".format(data['bin_path'], data['interesting'], data['func_name'], data['addr'], data['interesting_value'] if 'interesting_value' in data else 'None'))
    output_file.write("{},{},{},0x{},'{}'\n".format(data['bin_path'],data["interesting"],data["func_name"],data["addr"],data["interesting_value"] if 'interesting_value' in data else 'None'))

def alwaysDangerous(addr,caller,op,args,bin_path):
    return({'bin_path': bin_path, 'interesting': flat_api.getFunctionAt(addr), 'func_name': caller.getName(), 'addr': op.getSeqnum().getTarget()})
    #print(format(bin_path, flat_api.getFunctionAt(addr), caller.getName(), op.getSeqnum().getTarget(), args))

def dangerousFormatCheck(addr,caller,op,args,bin_path):
    if len(args) > 2:
        fstring = args[1]#op.getInput(1) # this is the argument which holds the string that references the func name
        if fstring != None:
            fstring_def = fstring.getDef()
            if fstring_def != None:
                    fstring_addr = flat_api.toAddr(fstring_def.getInput(0).getOffset())
                    fstring_string = getString(fstring_addr)
                    if "%s" in fstring_string:
                        return({'bin_path': bin_path, 'interesting': flat_api.getFunctionAt(addr), 'func_name': caller.getName(), 'addr': op.getSeqnum().getTarget(), 'interesting_value': fstring_string})

def variable3rdArg(addr,caller,op,args,bin_path):
    maxlen = args[2]
    if not maxlen.isConstant():
        return({'bin_path': bin_path, 'interesting': flat_api.getFunctionAt(addr), 'func_name': caller.getName(), 'addr': op.getSeqnum().getTarget(), 'interesting_value': maxlen})

def dangerousFormatWithVariableLenCheck(addr,caller,op,args,bin_path):
    fstring = args[2]#op.getInput(1) # this is the argument which holds the string that references the func name
    maxlen = args[1]
    if fstring != None:
        fstring_def = fstring.getDef()
        if fstring_def != None:
                fstring_addr = flat_api.toAddr(fstring_def.getInput(0).getOffset())
                fstring_string = getString(fstring_addr)
                if "%s" in fstring_string and not maxlen.isConstant():
                    return({'bin_path': bin_path, 'interesting': flat_api.getFunctionAt(addr), 'func_name': caller.getName(), 'addr': op.getSeqnum().getTarget(), 'interesting_value': fstring_string})

def variableOSCallCheck(addr,caller,op,args,bin_path):
    fstring = args[0]#op.getInput(1) # this is the argument which holds the string that references the func name
    if fstring != None:
        fstring_def = fstring.getDef()
        if fstring_def != None:
                fstring_addr = flat_api.toAddr(fstring_def.getInput(0).getOffset())
                fstring_string = getString(fstring_addr)
                if fstring_string == "":
                    return({'bin_path': bin_path, 'interesting': flat_api.getFunctionAt(addr), 'func_name': caller.getName(), 'addr': op.getSeqnum().getTarget()})
                    
def isHttpHeader(addr,caller,op,args,bin_path):
    fstring = args[0] # this is the argument which holds the string that references the func name
    if fstring != None:
        fstring_def = fstring.getDef()
        if fstring_def != None:
                fstring_addr = flat_api.toAddr(fstring_def.getInput(0).getOffset())
                fstring_string = getString(fstring_addr)
                if fstring_string.startswith("HTTP"):
                    return({'bin_path': bin_path, 'interesting': flat_api.getFunctionAt(addr), 'func_name': caller.getName(), 'addr': op.getSeqnum().getTarget(), 'interesting_value': fstring_string})
        

TARGET_FUNCS = {
    "sscanf": dangerousFormatCheck, 
    "__isoc99_sscanf": dangerousFormatCheck,
    "sprintf": dangerousFormatCheck,
    "vsprintf": dangerousFormatCheck,
    "snprintf": dangerousFormatWithVariableLenCheck,
    "vsnprintf": dangerousFormatWithVariableLenCheck,
    "system": variableOSCallCheck,
    "exec": variableOSCallCheck,
    "popen": variableOSCallCheck,
    "strcpy": alwaysDangerous,
    "stpcpy": alwaysDangerous,
    "strcat": alwaysDangerous,
    "strncpy": variable3rdArg,
    "strncat": variable3rdArg,
    "memcpy": variable3rdArg,
    "srand": alwaysDangerous,
    "fopen": variableOSCallCheck,
    "getenv": isHttpHeader,
    "setenv": isHttpHeader,
    }

# Step 1. Get functions that call the target function ('callers')
target_addr = 0
target_addrs = {}
callers = {}


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Search for potentially interesting calls to sprintf')
    parser.add_argument('bin', help='Path to binary used for analysis')
    parser.add_argument('--output', help='CSV output file containing interesting calls to analyze', default=None)

    args = parser.parse_args()
    if args.output == None:
        args.output = args.bin + "_analysis.csv"
    output = open(args.output,"w")

    bin_path = Path(args.bin)
    cgraph_name = bin_path.name
    project_location = Path('.ghidra_projects')

    with pyhidra.open_program(bin_path, project_location=project_location, project_name=bin_path.name, analyze=False) as flat_api:
        from ghidra.program.util import GhidraProgramUtilities
        from ghidra.app.script import GhidraScriptUtil  
        from ghidra.app.decompiler import DecompileOptions
        from ghidra.app.decompiler import DecompInterface      

        program: "ghidra.program.model.listing.Program" = flat_api.getCurrentProgram()        

        currentProgram = flat_api.getCurrentProgram()
        # analyze program if we haven't yet
        if GhidraProgramUtilities.shouldAskToAnalyze(program):
            GhidraScriptUtil.acquireBundleHostReference()
            flat_api.analyzeAll(program)
            GhidraProgramUtilities.markProgramAnalyzed(program)
            GhidraScriptUtil.releaseBundleHostReference()

        funcs = program.functionManager.getFunctions(True)
        myfunc = None

        for func in funcs:
            if func.getName() in TARGET_FUNCS.keys():
                myfunc = func
                target_addr = func.getEntryPoint()
                target_addrs[func.getEntryPoint()] = TARGET_FUNCS[func.getName()]
                references = flat_api.getReferencesTo(target_addr)
                xrefs = 0
                if func.getEntryPoint() not in callers.keys():
                    callers[func.getEntryPoint()] = []
                for xref in references:
                    call_addr = xref.getFromAddress()
                    caller = flat_api.getFunctionContaining(call_addr)
                    callers[func.getEntryPoint()].append(caller)
                    xrefs+=1
                

        # Step 2. Decompile all callers and find PCODE CALL operations leading to `target_add`
        options = DecompileOptions()
        monitor = ConsoleTaskMonitor()
        ifc = DecompInterface()
        ifc.setOptions(options)
        ifc.openProgram(currentProgram)

        for mycaller in callers.keys():
            for caller in list(set(callers[mycaller])):
                if caller == None:
                    continue
                try:
                    res = ifc.decompileFunction(caller, 60, monitor)
                    high_func = res.getHighFunction()
                    lsm = high_func.getLocalSymbolMap()
                    symbols = lsm.getSymbols()
                except:
                    print("Decompiler error")
                    continue
                
                if high_func:
                    opiter = high_func.getPcodeOps()
                    while opiter.hasNext():
                        op = opiter.next()
                        mnemonic = str(op.getMnemonic())
                        if mnemonic == "CALL":
                            inputs = op.getInputs()
                            addr = inputs[0].getAddress()
                            args = inputs[1:] # List of VarnodeAST types
                            if addr == mycaller:#in target_addrs.keys():
                                data = target_addrs[addr](addr,caller,op,args, bin_path)
                                if data != None:
                                    doOutput(target_addrs[addr](addr,caller,op,args, bin_path),output)
    output.close()

