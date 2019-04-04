import bridge


class GhidraBridge():
    def __init__(self, host=bridge.DEFAULT_HOST, ghidra_server_port=bridge.DEFAULT_SERVER_PORT, local_server_port=bridge.DEFAULT_CLIENT_PORT):
        self.bridge = bridge.Bridge(
            host=host, server_port=local_server_port, client_port=ghidra_server_port)

    def get_flat_api(self, namespace=None):
        """ Get the flat API (as well as the GhidraScript API). If a namespace is provided (e.g., locals() or globals(), load the methods and fields from the APIs into that namespace. Otherwise, just return the bridged module """

        remote_main = self.bridge.remote_import("__main__")

        if namespace is not None:
            # load in all the attrs from remote main, skipping the double underscores
            for attr in remote_main._bridge_attrs:
                if not attr.startswith("__"):
                    namespace[attr] = getattr(remote_main, attr)

        return remote_main

    def get_ghidra_api(self):
        """ get the ghidra api - `ghidra = bridge.get_ghidra_api()` equivalent to doing `import ghidra` in your script """
        return self.bridge.remote_import("ghidra")

    def __enter__(self):
        return self.get_flat_api()

    def __exit__(self, type, value, traceback):
        self.bridge.shutdown()
