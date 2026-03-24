dtm = program.getDataTypeManager()

# By path
dt = dtm.getDataType("/CategoryName/TypeName")

# Search by name
results = []
dtm.findDataTypes("MyStruct", results)

# Built-in primitives (no resolve needed)
from ghidra.program.model.data import (
    ByteDataType,
    WordDataType,
    DWordDataType,
    QWordDataType,
    IntegerDataType,
    LongDataType,
    CharDataType,
    BooleanDataType,
    FloatDataType,
    DoubleDataType,
    PointerDataType,
    VoidDataType,
)
