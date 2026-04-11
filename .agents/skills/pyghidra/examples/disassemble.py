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
    listing = program.getListing()
    address_space = program.getAddressFactory().getDefaultAddressSpace()

    # One instruction at a known address
    address = address_space.getAddress(0x1234)
    instruction = listing.getInstructionAt(address)
    if instruction is not None:
        print(f"{instruction.getAddress()}  {instruction}")

    # Instructions in a function body
    function = program.getFunctionManager().getFunctionContaining(address)
    if function is not None:
        instructions = listing.getInstructions(function.getBody(), True)
        for instruction in instructions:
            print(f"{instruction.getAddress()}  {instruction}")
