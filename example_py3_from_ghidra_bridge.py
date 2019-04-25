# Example script that demonstrates running a python3 (or technically, py2 should work) script outside the Ghidra interpreter, to use networkx to graph a function. Requires networkx installed in the external environment.
# @author justfoxing
# @category Examples

import argparse


def run_script(server_host, server_port):
    import ghidra_bridge

    # load something ghidra doesn't have
    import networkx

    print("Running inside the bridge!")

    # create the bridge and load the flat API/ghidra modules into the namespace
    with ghidra_bridge.GhidraBridge(connect_to_host=server_host, connect_to_port=server_port, namespace=globals()):
        # grab the current function
        function = currentProgram.getFunctionManager().getFunctionContaining(currentAddress)

        if function is None:
            raise Exception(
                "Current address {} not within a function".format(currentAddress))

        print("Graphing {}:{}".format(function, function.getEntryPoint()))

        model = ghidra.program.model.block.BasicBlockModel(currentProgram)

        # get the first code block in the function
        code_block = model.getFirstCodeBlockContaining(
            function.getEntryPoint(), monitor)

        graph = networkx.DiGraph()

        # step through the code blocks, adding them to a networkx graph
        to_visit_list = [code_block]
        visited_list = []

        while len(to_visit_list) > 0:
            visit_block = to_visit_list.pop()
            src_block_address = visit_block.getFirstStartAddress().getOffset()

            # mark as visited
            visited_list.append(src_block_address)

            dest_it = visit_block.getDestinations(monitor)
            dest_ref = dest_it.next()
            while dest_ref is not None:
                dest_block = dest_ref.getDestinationBlock()

                dest_address = dest_block.getFirstStartAddress().getOffset()

                # add an edge
                graph.add_edge(src_block_address, dest_address)

                # add the destination to the visit list, if we haven't already visited it
                if dest_address not in visited_list and dest_address not in [block.getFirstStartAddress().getOffset() for block in to_visit_list]:
                    to_visit_list.append(dest_block)

                dest_ref = dest_it.next()

        # visits completed
        # can now perform graph analysis on the graph... or just print the edges
        print(graph.edges)


if __name__ == "__main__":

    in_ghidra = False
    try:
        import ghidra
        # we're in ghidra!
        in_ghidra = True
    except ModuleNotFoundError:
        # not ghidra
        pass

    if in_ghidra:
        import ghidra_bridge_server
        script_file = getSourceFile().getAbsolutePath()
        # spin up a ghidra_bridge_server and spawn the script in external python to connect back to it
        ghidra_bridge_server.run_script_across_ghidra_bridge(script_file)
    else:
        # we're being run outside ghidra! (almost certainly from spawned by run_script_across_ghidra_bridge())

        parser = argparse.ArgumentParser(
            description="Example py3 script that's expected to be called from ghidra with a bridge")
        # the script needs to handle these command-line arguments and use them to connect back to the ghidra server that spawned it
        parser.add_argument("--connect_to_host", type=str, required=False,
                            default="127.0.0.1", help="IP to connect to the ghidra_bridge server")
        parser.add_argument("--connect_to_port", type=int, required=True,
                            help="Port to connect to the ghidra_bridge server")

        args = parser.parse_args()

        run_script(server_host=args.connect_to_host,
                   server_port=args.connect_to_port)
