import bridge

class GhidraBridge(object):
    def __init__(self, host=bridge.DEFAULT_HOST, ghidra_server_port=bridge.DEFAULT_SERVER_PORT, local_server_port=bridge.DEFAULT_CLIENT_PORT):
        self.bridge = bridge.Bridge(host=host, server_port=local_server_port, client_port=ghidra_server_port)
        
    def get_flat_api(self):
        # get the ghidra flat api loaded into main, so you can call getState directly on that
        return self.bridge.remote_import("__main__")
        
    def get_ghidra_api(self):
        # get the ghidra api - `ghidra = bridge.get_ghidra_api()` equivalent to doing `import ghidra` in your script
        return self.bridge.remote_import("ghidra")
        
    def __enter__(self):
        return self.get_flat_api()
        
    def __exit__(self, type, value, traceback):
        self.bridge.shutdown()
