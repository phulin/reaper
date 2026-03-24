from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.decompiler import DecompileOptions
from ghidra.program.model.symbol import SourceType

with pyghidra.transaction(program, "Rename parameter"):
    sym_map = hf.getLocalSymbolMap()
    for i in range(sym_map.getNumParams()):
        param_sym = sym_map.getParamSymbol(i)
        if param_sym.getName() == "param_1":
            HighFunctionDBUtil.updateDBVariable(
                param_sym, "ctx", None, SourceType.USER_DEFINED
            )

# Or commit all parameter names at once:
with pyghidra.transaction(program, "Commit params"):
    HighFunctionDBUtil.commitParamsToDatabase(
        hf,
        True,                                        # useDataTypes
        HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT,
        SourceType.USER_DEFINED
    )
