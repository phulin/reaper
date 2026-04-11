from ghidra.program.model.data import (
    StructureDataType,
    DataTypeConflictHandler,
    IntegerDataType,
    PointerDataType,
)

dtm = program.getDataTypeManager()

with pyghidra.transaction(program, "Add struct"):
    # Create the structure
    s = StructureDataType("MyStruct", 0, dtm)
    s.add(IntegerDataType.dataType, 4, "field_count", None)
    s.add(PointerDataType.dataType, 8, "field_ptr", None)

    # Resolve into the program's type manager
    resolved = dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER)
