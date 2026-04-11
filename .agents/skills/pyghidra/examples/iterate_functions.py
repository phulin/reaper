import pyghidra

pyghidra.start()

from ghidra.framework.model import ProjectLocator
from ghidra.pyghidra import PyGhidraProjectManager


def open_read_only_project(project_path, project_name):
    project_locator = ProjectLocator(str(project_path), project_name)
    project_manager = PyGhidraProjectManager()
    return project_manager.openProject(project_locator, True, False)


project = open_read_only_project("/path/to/project_dir", "project_name")

with pyghidra.program_context(project, "/program_name") as program:
    func_mgr = program.getFunctionManager()
    address_space = program.getAddressFactory().getDefaultAddressSpace()

    # All functions
    for func in func_mgr.getFunctions(True):
        ...

    # Function at address
    func = func_mgr.getFunctionContaining(address_space.getAddress(0x1234))
