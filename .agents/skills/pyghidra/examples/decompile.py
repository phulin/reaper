import pyghidra

pyghidra.start()

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.framework.model import ProjectLocator
from ghidra.pyghidra import PyGhidraProjectManager
from ghidra.util.task import TaskMonitor


def open_read_only_project(project_path, project_name):
    project_locator = ProjectLocator(str(project_path), project_name)
    project_manager = PyGhidraProjectManager()
    return project_manager.openProject(project_locator, True, False)


def get_decompiler(program):
    decomp = DecompInterface()
    decomp.setOptions(DecompileOptions())
    decomp.openProgram(program)
    return decomp


project = open_read_only_project("/path/to/project_dir", "project_name")

with pyghidra.program_context(project, "/program_name") as program:
    address_space = program.getAddressFactory().getDefaultAddressSpace()

    # Decompile a function
    decomp = get_decompiler(program)
    func = program.getFunctionManager().getFunctionAt(
        address_space.getAddress(0x1234)
    )
    result = decomp.decompileFunction(func, 30, TaskMonitor.DUMMY)

    if result.decompileCompleted():
        # Get C pseudocode as a string
        c_code = result.getDecompiledFunction().getC()

        # Get the structured representation (HighFunction)
        hf = result.getHighFunction()
    else:
        print(result.getErrorMessage())

    decomp.dispose()
