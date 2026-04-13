"""Win16 API stub handler dispatch table.

Re-exports the merged STUB_HANDLERS dict assembled from per-DLL modules,
plus the shared stack-reading helpers.
"""

from simtower.stub_helpers import _read_stack_dword, _read_stack_word
from simtower.stubs_gdi import STUB_HANDLERS_GDI
from simtower.stubs_kernel import STUB_HANDLERS_KERNEL
from simtower.stubs_misc import STUB_HANDLERS_MISC
from simtower.stubs_user import STUB_HANDLERS_USER

STUB_HANDLERS = {
    **STUB_HANDLERS_KERNEL,
    **STUB_HANDLERS_GDI,
    **STUB_HANDLERS_USER,
    **STUB_HANDLERS_MISC,
}

__all__ = [
    "STUB_HANDLERS",
    "_read_stack_word",
    "_read_stack_dword",
]
