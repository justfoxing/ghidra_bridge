
from IPython.core.magic import register_cell_magic


@register_cell_magic
def remote_eval(line, cell):
    ghidra_bridge = globals()[line.strip()]


    # Horrible hack to make the currentProgram variable available
    # TODO: find some better way, maybe involving AST rewriting or sending the mapping from variable to handle with the message
    handle = currentProgram._bridge_handle
    code = cell.replace("currentProgram", "self.handle_dict['%s'].local_obj" % handle)
    return ghidra_bridge.bridge.remote_eval(code)
