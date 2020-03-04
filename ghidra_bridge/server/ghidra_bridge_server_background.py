# Run a ghidra_bridge server in background/no-GUI-mode for external python environments to interact with
# @author justfoxing
# @category Bridge

from ghidra_bridge_server import GhidraBridgeServer

if __name__ == "__main__":
    GhidraBridgeServer.run_server(background=True)
