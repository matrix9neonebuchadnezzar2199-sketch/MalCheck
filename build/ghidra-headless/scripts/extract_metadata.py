# Ghidra Headless PostScript — imports, sections, string sample
import json

args = getScriptArgs()
output_path = args[0] if len(args) > 0 else "/output/metadata.json"

metadata = {
    "program": currentProgram.getName(),
    "language": str(currentProgram.getLanguage().getLanguageID()),
    "compiler": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
    "image_base": str(currentProgram.getImageBase()),
    "executable_format": currentProgram.getExecutableFormat(),
    "imports": [],
    "exports": [],
    "memory_blocks": [],
    "strings_sample": [],
}

sym_table = currentProgram.getSymbolTable()
try:
    for sym in sym_table.getAllSymbols(True):
        try:
            if sym.isExternal():
                metadata["imports"].append({
                    "name": sym.getName(),
                    "address": str(sym.getAddress()),
                    "library": str(sym.getParentNamespace()),
                })
        except Exception:
            pass
except Exception:
    pass

try:
    for sym in sym_table.getDefinedSymbols():
        try:
            if sym.isExternalEntryPoint():
                metadata["exports"].append({
                    "name": sym.getName(),
                    "address": str(sym.getAddress()),
                })
        except Exception:
            pass
except Exception:
    pass

try:
    for block in currentProgram.getMemory().getBlocks():
        metadata["memory_blocks"].append({
            "name": block.getName(),
            "start": str(block.getStart()),
            "size": block.getSize(),
            "permissions": "{}{}{}".format(
                "r" if block.isRead() else "-",
                "w" if block.isWrite() else "-",
                "x" if block.isExecute() else "-",
            ),
        })
except Exception:
    pass

try:
    from ghidra.program.util import DefinedDataIterator
    count = 0
    for data in DefinedDataIterator.definedStrings(currentProgram):
        if count >= 200:
            break
        try:
            val = data.getValue()
            if val is not None and hasattr(val, "toString"):
                val = val.toString()
        except Exception:
            val = None
        metadata["strings_sample"].append({
            "address": str(data.getAddress()),
            "value": str(val) if val is not None else "",
        })
        count += 1
except Exception:
    pass

with open(output_path, "w") as f:
    json.dump(metadata, f, indent=2, ensure_ascii=False, default=str)

print("[+] Metadata exported -> {}".format(output_path))
