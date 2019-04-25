import bridge

""" Use this list to exclude modules loaded on the remote side from being loaded into our namespace.
This prevents the ghidra_bridge imported by ghidra_bridge_server being loaded over the local ghidra_bridge and causing issues. 
You probably only want this for stuff imported by the ghidra_bridge_server script that might conflict on the local side.
"""
EXCLUDED_REMOTE_IMPORTS = ["logging", "ghidra_bridge"]

class GhidraBridge():
    def __init__(self, server_host="127.0.0.1", server_port=0, connect_to_host=bridge.DEFAULT_HOST, connect_to_port=bridge.DEFAULT_SERVER_PORT, start_in_background=True, loglevel=None):
        """ Set up a bridge. Default settings are for a client - connect to the default ghidra bridge server, set up a listening server on a random port, and start it in a background thread. For a ghidra bridge server, specify the server_port, set connect_to_* to None and set start_in_background to False """
        self.bridge = bridge.Bridge(server_host=server_host, server_port=server_port,
                                    connect_to_host=connect_to_host, connect_to_port=connect_to_port,
                                    start_in_background=start_in_background, loglevel=loglevel)

    def get_flat_api(self, namespace=None):
        """ Get the flat API (as well as the GhidraScript API). If a namespace is provided (e.g., locals() or globals(), load the methods and fields from the APIs into that namespace. Otherwise, just return the bridged module """

        remote_main = self.bridge.remote_import("__main__")

        if namespace is not None:
            # load in all the attrs from remote main, skipping the double underscores and avoiding overloading our own ghidra_bridge
            for attr in remote_main._bridge_attrs:
                if not attr.startswith("__") and attr not in EXCLUDED_REMOTE_IMPORTS:
                    namespace[attr] = getattr(remote_main, attr)

        return remote_main

    def get_ghidra_api(self):
        """ get the ghidra api - `ghidra = bridge.get_ghidra_api()` equivalent to doing `import ghidra` in your script """
        return self.bridge.remote_import("ghidra")

    def __enter__(self):
        return self.get_flat_api()

    def __exit__(self, type, value, traceback):
        self.bridge.shutdown()
