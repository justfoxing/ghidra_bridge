
from IPython.core.magic import register_line_cell_magic

import logging



def activate_remote_eval_magic(ghidra_bridge):
    """
    This function registers the "remote_eval" cell and line magic as a convient wrapper around the remote_eval functionality
    Example setup:
    ```
    import ghidra_bridge
    import ghidra_bridge.ipython_helpers
    b = ghidra_bridge.GhidraBridge(namespace=globals())
    ghidra_bridge.ipython_helpers.activate_remote_eval_magic(b, currentProgram)
    ```
    Example usage:
    ```
    In [13]: %remote_eval [ f.name for f in currentProgram.functionManager.getFunctions(True)]
    Out[13]: ['_init', '_start', ...]
    ```


    :param GhidraBridge ghidra_bridge: The bridge that should be used
    :return:
    """
    @register_line_cell_magic
    def remote_eval(line, cell=None):
        if cell:
            return ghidra_bridge.bridge.remote_eval(cell)
        else:
            return ghidra_bridge.bridge.remote_eval(line)
