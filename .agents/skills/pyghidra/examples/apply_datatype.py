from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType

dtm = program.getDataTypeManager()

with pyghidra.transaction(program, "Apply struct type"):
    resolved_type = dtm.getDataType(
        "/MyStruct"
    )  # or use resolved from create_struct.py
    HighFunctionDBUtil.updateDBVariable(
        sym, None, resolved_type, SourceType.USER_DEFINED
    )
