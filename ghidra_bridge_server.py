# Run a ghidra_bridge server for external python environments to interact with
# @author justfoxing
# @category Bridge

# NOTE: any imports here may need to be excluded in ghidra_bridge
import logging
import subprocess
from ghidra_bridge import bridge


class GhidraBridgeServer(object):
    """ Class mostly used to collect together functions and variables that we don't want contaminating the __main__ module
        that gets sent back to clients

        NOTE: this class needs to be excluded from ghidra_bridge - it'll contaminate __main__
    """

    @staticmethod
    def run_server(server_host=bridge.DEFAULT_HOST, server_port=bridge.DEFAULT_SERVER_PORT):
        """ Run a ghidra_bridge_server (forever)
            server_host - what address the server should listen on
            server_port - what port the server should listen on
        """
        bridge.BridgeServer(server_host=server_host,
                            server_port=server_port, loglevel=logging.DEBUG).run()

    @staticmethod
    def run_script_across_ghidra_bridge(script_file, python="python", argstring=""):
        """ Spin up a ghidra_bridge_server and spawn the script in external python to connect back to it. Useful in scripts being triggered from
            inside ghidra that need to use python3 or packages that don't work in jython

            The called script needs to handle the --connect_to_host and --connect_to_port command-line arguments and use them to start
            a ghidra_bridge client to talk back to the server.

            Specify python to control what the script gets run with. Defaults to whatever python is in the shell - if changing, specify a path
            or name the shell can find.
            Specify argstring to pass further arguments to the script when it starts up.
        """

        # spawn a ghidra bridge server - use server port 0 to pick a random port
        server = bridge.BridgeServer(
            server_host="127.0.0.1", server_port=0, loglevel=logging.INFO)
        # start it running in a background thread
        server.start()

        try:
            # work out where we're running the server
            server_host, server_port = server.bridge.get_server_info()

            print("Running " + script_file)

            # spawn an external python process to run against it

            try:
                output = subprocess.check_output("{python} {script} --connect_to_host={host} --connect_to_port={port} {argstring}".format(
                    python=python, script=script_file, host=server_host, port=server_port, argstring=argstring), stderr=subprocess.STDOUT, shell=True)
                print(output)
            except subprocess.CalledProcessError as exc:
                print("Failed ({}):{}".format(exc.returncode, exc.output))

            print(script_file + " completed")

        finally:
            # when we're done with the script, shut down the server
            server.bridge.shutdown()


if __name__ == "__main__":
    GhidraBridgeServer.run_server()
