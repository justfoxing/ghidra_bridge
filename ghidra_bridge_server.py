# Run a ghidra_bridge server for external python environments to interact with
# @author justfoxing
# @category Bridge

# NOTE: any imports here may need to be excluded in ghidra_bridge
import logging
import subprocess
from ghidra_bridge import bridge

# NOTE: we definitely DON'T want to exclude ghidra from ghidra_bridge :P
import ghidra

class GhidraBridgeServer(object):
    """ Class mostly used to collect together functions and variables that we don't want contaminating the global namespace
        variables set in remote clients

        NOTE: this class needs to be excluded from ghidra_bridge - it doesn't need to be in the globals, if people want it and
        know what they're doing, they can get it from the BridgedObject for the main module
    """
    
    class InteractiveListener(ghidra.framework.model.ToolListener):
        """ Class to handle registering for plugin events associated with the GUI
            environment, and sending them back to clients running in interactive mode
            so they can update their variables 
            
            We define the interactive listener on the server end, so it can
            cleanly recover from bridge failures when trying to send messages back. If we
            let it propagate exceptions up into Ghidra, the GUI gets unhappy and can stop
            sending tool events out 
        """
        tool = None
        callback_fn = None
          
        def __init__(self, tool, callback_fn):
            """ Create with the tool to listen to (from state.getTool() - won't change during execution)
                and the callback function to notify on the client end (should be the update_vars function) """
            self.tool = tool
            self.callback_fn = callback_fn

            # register the listener against the remote tool
            tool.addToolListener(self)

        def stop_listening(self):
            # we're done, make sure we remove the tool listener
            self.tool.removeToolListener(self)

        def processToolEvent(self, plugin_event):
            """ Called by the ToolListener interface """
            try:
		self.callback_fn._bridge_conn.logger.debug("InteractiveListener got event: " + str(plugin_event))

                event_name = plugin_event.getEventName()
                if "Location" in event_name:
                    self.callback_fn(currentProgram=plugin_event.getProgram(
                    ), currentLocation=plugin_event.getLocation())
                elif "Selection" in event_name:
                    self.callback_fn(currentProgram=plugin_event.getProgram(
                    ), currentSelection=plugin_event.getSelection())
                elif "Highlight" in event_name:
                    self.callback_fn(currentProgram=plugin_event.getProgram(
                    ), currentHighlight=plugin_event.getHighlight())
            except Exception as e:
                # any exception, we just want to bail and shut down the listener. 
                # most likely case is the bridge connection has gone down. 
                self.stop_listening()
                self.callback_fn._bridge_conn.logger.error("InteractiveListener failed trying to callback client: " + str(e))

    @staticmethod
    def run_server(server_host=bridge.DEFAULT_HOST, server_port=bridge.DEFAULT_SERVER_PORT):
        """ Run a ghidra_bridge_server (forever)
            server_host - what address the server should listen on
            server_port - what port the server should listen on
        """
        bridge.BridgeServer(server_host=server_host,
                            server_port=server_port, loglevel=logging.INFO).run()

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
