# Ghidra Headless PostScript — decompile functions to pseudo-C
# Usage: -postScript decompile_simple.py <output_filepath>

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

args = getScriptArgs()
output_path = args[0] if len(args) > 0 else "/output/decompiled.c"

decomp = DecompInterface()
if not decomp.openProgram(currentProgram):
    print("[!] Decompiler could not open program")
    raise Exception("DecompInterface.openProgram failed")

monitor = ConsoleTaskMonitor()
function_manager = currentProgram.getFunctionManager()
functions = function_manager.getFunctions(True)

output_lines = []
function_summary = []

output_lines.append("// ==============================================")
output_lines.append("// Ghidra Headless Decompiler Output")
output_lines.append("// Program: {}".format(currentProgram.getName()))
output_lines.append("// ==============================================")
output_lines.append("")

count = 0
for func in functions:
    try:
        result = decomp.decompileFunction(func, 60, monitor)
        if result is not None and result.decompileCompleted():
            high = result.getDecompiledFunction()
            if high is not None:
                code = high.getC()
                output_lines.append("// ---- Function: {} @ {} ----".format(
                    func.getName(), func.getEntryPoint()))
                output_lines.append(code)
                output_lines.append("")

                function_summary.append({
                    "name": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "size": func.getBody().getNumAddresses(),
                    "has_decompile": True
                })
                count += 1
            else:
                function_summary.append({
                    "name": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "size": func.getBody().getNumAddresses(),
                    "has_decompile": False
                })
        else:
            function_summary.append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses(),
                "has_decompile": False
            })
    except Exception as e:
        print("[-] Failed to decompile {}: {}".format(func.getName(), str(e)))

with open(output_path, "w") as f:
    f.write("\n".join(output_lines))

summary_path = output_path.replace(".c", "_summary.json")
with open(summary_path, "w") as f:
    json.dump({
        "program": currentProgram.getName(),
        "total_functions_decompiled": count,
        "functions": function_summary
    }, f, indent=2)

print("[+] Decompiled {} functions -> {}".format(count, output_path))
print("[+] Summary -> {}".format(summary_path))
