func_mgr = program.getFunctionManager()

# All functions
for func in func_mgr.getFunctions(True):
    ...

# Function at address
func = func_mgr.getFunctionContaining(toAddr(0x1234))
