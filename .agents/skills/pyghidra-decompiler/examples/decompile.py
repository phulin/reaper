from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import TaskMonitor

def get_decompiler(program):
    decomp = DecompInterface()
    decomp.setOptions(DecompileOptions())
    decomp.openProgram(program)
    return decomp

# Decompile a function
decomp = get_decompiler(program)
func = program.getFunctionManager().getFunctionAt(toAddr(0x1234))
result = decomp.decompileFunction(func, 30, TaskMonitor.DUMMY)

if result.decompileCompleted():
    # Get C pseudocode as a string
    c_code = result.getDecompiledFunction().getC()

    # Get the structured representation (HighFunction)
    hf = result.getHighFunction()
else:
    print(result.getErrorMessage())

decomp.dispose()
