from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType

# Must be inside a transaction
with pyghidra.transaction(program, "Rename local variable"):
    sym_map = hf.getLocalSymbolMap()
    for sym in sym_map.getSymbols():
        if sym.getName() == "local_10":
            HighFunctionDBUtil.updateDBVariable(
                sym,
                "my_new_name",  # new name, or None to keep current
                None,  # new DataType, or None to keep current
                SourceType.USER_DEFINED,
            )
            break

# After writing, the existing HighFunction is stale — re-decompile to get updated names.
