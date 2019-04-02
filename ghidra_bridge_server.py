import ghidra_bridge

def run_server(host=ghidra_bridge.bridge.DEFAULT_HOST, server_port=ghidra_bridge.bridge.DEFAULT_SERVER_PORT, client_port=ghidra_bridge.bridge.DEFAULT_CLIENT_PORT):
    server = ghidra_bridge.GhidraBridge(host=host, local_server_port=server_port, ghidra_server_port=client_port)
    server.bridge.start()


if __name__=="__main__":
    run_server()