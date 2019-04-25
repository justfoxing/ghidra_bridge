# Run a ghidra_bridge server for external python environments to interact with
# @author justfoxing
# @category Bridge

# NOTE: any imports here may need to be excluded in ghidra_bridge
import logging

import ghidra_bridge


def run_server(server_host=ghidra_bridge.bridge.DEFAULT_HOST, server_port=ghidra_bridge.bridge.DEFAULT_SERVER_PORT):
    server = ghidra_bridge.GhidraBridge(
        server_host=server_host, server_port=server_port, connect_to_host=None, connect_to_port=None, start_in_background=False, loglevel=logging.INFO)
    server.bridge.start()


if __name__ == "__main__":
    run_server()
