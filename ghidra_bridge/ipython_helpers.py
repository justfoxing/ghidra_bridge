
from IPython.core.magic import register_cell_magic

import logging



def activate_remote_eval_magic(ghidra_bridge, currentProgram):
    """
    This function registers the "remote_eval" cell magic.
    Example setup:
    ```
    import ghidra_bridge
    import ghidra_bridge.ipython_helpers
    b = ghidra_bridge.GhidraBridge(namespace=globals())
    ghidra_bridge.ipython_helpers.activate_remote_eval_magic(b, currentProgram)
    ```
    Example usage:
    ```
    %%remote_eval
    [ f.name for f in currentProgram.functionManager.getFunctions(True)]
    ```
    If this expression would be evaluated on the client, it would take 2-3 minutes for a binary with ~8k functions due to ~8k roundtrips to call __next__ and ~8k roundtrips to access the name attribute
    Instead this magic takes the entire cell as a string, performs simple string replacement to exchange the currentProgram variable with the expression that accesses the handle_dict on the server side, sends it to the server, which evaluates it and sends the entire result back in one JSON message. This takes only a few hundred milliseconds at most.

    Caveats:
    - The expression `[ f for f in currentProgram.functionManager.getFunctions(True)]` still takes roughly a 1  minute to finish. Almost the entire time is spent sending the message to the client. This issue requires a deeper change in the RPC implementation to increase throughput or reduce message size
    - currently only simple string replacement is used which can't distinguish between the string literal `'currentProgram'` and the variable `currentProgram`. This could be addressed with parsing and AST manipulation to replace all bridged references with their appropriate references on the server side.
    - because currentProgram is passed once when activated it is never updated. If the reference ever changes this will use an outdated one. Workaround is to just rerun the activation function

    :param GhidraBridge ghidra_bridge: The bridge that should be used
    :param BridgedObject currentProgram: The BridgedObject that is currently representing the currentProgram
    :return:
    """
    logging.warning("Remote eval is still HEAVILY EXPERIMENTAL, see documentation of this function for details")
    @register_cell_magic
    def remote_eval(line, cell):
        # horrible hack to make the currentProgram variable available
        # todo: find some better way, maybe involving ast rewriting or sending the mapping from variable to handle with the message
        handle = currentProgram._bridge_handle
        code = cell.replace("currentProgram", "self.handle_dict['%s'].local_obj" % handle)
        return ghidra_bridge.bridge.remote_eval(code)
