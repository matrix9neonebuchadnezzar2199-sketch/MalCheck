# Ghidra Headless PostScript — export function list as JSON
import json

args = getScriptArgs()
output_path = args[0] if len(args) > 0 else "/output/functions.json"

fm = currentProgram.getFunctionManager()
functions = []

for func in fm.getFunctions(True):
    try:
        cc = func.getCallingConventionName()
    except Exception:
        cc = None
    try:
        pc = func.getParameterCount()
    except Exception:
        pc = -1
    functions.append({
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "size": func.getBody().getNumAddresses(),
        "is_thunk": func.isThunk(),
        "is_external": func.isExternal(),
        "calling_convention": cc,
        "param_count": pc,
    })

with open(output_path, "w") as f:
    json.dump({"program": currentProgram.getName(),
               "function_count": len(functions),
               "functions": functions}, f, indent=2)

print("[+] Exported {} functions -> {}".format(len(functions), output_path))
