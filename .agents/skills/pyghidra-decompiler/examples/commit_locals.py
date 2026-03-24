from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType

with pyghidra.transaction(program, "Commit locals"):
    HighFunctionDBUtil.commitLocalNamesToDatabase(hf, SourceType.USER_DEFINED)
