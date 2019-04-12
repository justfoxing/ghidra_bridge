# Example script that demonstrates running a python3 (or technically, py2 should work) script outside the Ghidra interpreter, to use networkx to graph a function. Requires networkx installed in the external environment.
# @author justfoxing
# @category Examples


import argparse
import subprocess
import ghidra_bridge


def run_script(server_host, server_port):
    # load something ghidra doesn't have
    import networkx

    print("Running inside the bridge!")

    # create the bridge
    bridge = ghidra_bridge.GhidraBridge(
        connect_to_host=server_host, connect_to_port=server_port)

    # load the ghidra modules
    bridge.get_flat_api(namespace=globals())
    ghidra = bridge.get_ghidra_api()

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
    # check if we're being called from ghidra
    in_ghidra = False

    try:
        import ghidra
        # ghidra!
        in_ghidra = True
    except ModuleNotFoundError:
        # not ghidra
        pass

    if in_ghidra:
        # spawn a ghidra bridge server - use server port 0 to pick a random port
        server = ghidra_bridge.GhidraBridge(
            server_host="127.0.0.1", server_port=0, connect_to_host=None, connect_to_port=None, start_in_background=True)

        try:
            # work out where it's running the server
            server_host, server_port = server.bridge.get_server_info()

            script_file = getSourceFile().getAbsolutePath()

            print("Running " + script_file)
            # then spawn an external python process to run against it

            try:
                output = subprocess.check_output("python {script} --connect_to_host={host} --connect_to_port={port}".format(
                    script=script_file, host=server_host, port=server_port), stderr=subprocess.STDOUT, shell=True)
                print(output)
            except subprocess.CalledProcessError as exc:
                print("Failed ({}):{}".format(exc.returncode, exc.output))

            print(script_file + " completed")

        finally:
            # when we're done with the script, shut down the server
            server.bridge.shutdown()

    else:
        # we're being run outside ghidra!

        parser = argparse.ArgumentParser(
            description="Example py3 script that's expected to be called from ghidra with a bridge")
        parser.add_argument("--connect_to_host", type=str, required=False,
                            default=None, help="IP to connect to the ghidra_bridge server")
        parser.add_argument("--connect_to_port", type=int, required=True,
                            help="Port to connect to the ghidra_bridge server")

        args = parser.parse_args()

        run_script(server_host=args.connect_to_host,
                   server_port=args.connect_to_port)
