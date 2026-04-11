import pyghidra

pyghidra.start()

from ghidra.framework.model import ProjectLocator
from ghidra.program.model.data import (
    BooleanDataType,
    ByteDataType,
    CharDataType,
    DoubleDataType,
    DWordDataType,
    FloatDataType,
    IntegerDataType,
    LongDataType,
    PointerDataType,
    QWordDataType,
    VoidDataType,
    WordDataType,
)
from ghidra.pyghidra import PyGhidraProjectManager


def open_read_only_project(project_path, project_name):
    project_locator = ProjectLocator(str(project_path), project_name)
    project_manager = PyGhidraProjectManager()
    return project_manager.openProject(project_locator, True, False)


project = open_read_only_project("/path/to/project_dir", "project_name")

with pyghidra.program_context(project, "/program_name") as program:
    dtm = program.getDataTypeManager()

    # By path
    dt = dtm.getDataType("/CategoryName/TypeName")

    # Search by name
    results = []
    dtm.findDataTypes("MyStruct", results)
