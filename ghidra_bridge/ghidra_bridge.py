import sys
import weakref
import pydoc

from jfx_bridge import bridge

from .server.ghidra_bridge_port import DEFAULT_SERVER_PORT

""" Use this list to exclude modules and names loaded by the remote ghidra_bridge side from being loaded into namespaces (they'll 
still be present in the BridgedObject for the __main__ module. This prevents the ghidra_bridge imported by ghidra_bridge_server 
being loaded over the local ghidra_bridge and causing issues. You probably only want this for stuff imported by the ghidra_bridge_server
script that might conflict on the local side (or which is totally unnecessary on the local side, like GhidraBridgeServer).
"""
EXCLUDED_REMOTE_IMPORTS = ["logging", "subprocess", "sys",
                           "ghidra_bridge", "bridge", "GhidraBridgeServer"]

GHIDRA_BRIDGE_NAMESPACE_TRACK = "__ghidra_bridge_namespace_track__"


def get_listing_panel(tool, ghidra):
    """ Get the code listing UI element, so we can get up-to-date location/highlight/selection """
    cvs = tool.getService(ghidra.app.services.CodeViewerService)
    return cvs.getListingPanel()


class GhidraBridge():
    def __init__(self, connect_to_host=bridge.DEFAULT_HOST, connect_to_port=DEFAULT_SERVER_PORT, loglevel=None, namespace=None, interactive_mode=None, response_timeout=bridge.DEFAULT_RESPONSE_TIMEOUT, hook_import=False):
        """ Set up a bridge. Default settings connect to the default ghidra bridge server,

        If namespace is specified (e.g., locals() or globals()), automatically calls get_flat_api() with that namespace. 

        loglevel for what logging messages you want to capture

        interactive_mode should auto-detect interactive environments (e.g., ipython or not in a script), but 
        you can force it to True or False if you need to. False is normal ghidra script behaviour 
        (currentAddress/getState() etc locked to the values when the script started. True is closer to the 
        behaviour in the Ghidra Jython shell - current*/getState() reflect the current values in the GUI

        response_timeout is how long to wait for a response before throwing an exception, in seconds
        
        Set hook_import to True to add a hook to the import system to allowing importing remote modules
        """
        self.bridge = bridge.BridgeClient(
            connect_to_host=connect_to_host, connect_to_port=connect_to_port, loglevel=loglevel, response_timeout=response_timeout, hook_import=hook_import)

        if interactive_mode is None:
            # from https://stackoverflow.com/questions/2356399/tell-if-python-is-in-interactive-mode, sys.ps1 only present in interactive interpreters
            interactive_mode = bool(getattr(sys, 'ps1', sys.flags.interactive))
        self.interactive_mode = interactive_mode
        self.interactive_listener = None

        self.flat_api_modules_list = []
        self.namespace_list = []
        self.namespace = None
        if namespace is not None:
            if connect_to_host is None or connect_to_port is None:
                raise Exception(
                    "Can't get_flat_api for the namespace if connect_to_host/port are none - need a server!")

            # track the namespace we loaded with - if we're part of an __enter__/__exit__ setup, we'll use it to automatically unload the flat api
            self.namespace = namespace
            self.get_flat_api(namespace=self.namespace)

    def get_flat_api(self, namespace=None):
        """ Get the flat API (as well as the GhidraScript API). If a namespace is provided (e.g., locals() or globals()), load the methods and
        fields from the APIs into that namespace (call unload_flat_api() to remove). Otherwise, just return the bridged module.

        Note that the ghidra and java packages are always loaded into the remote script's side, so get_flat_api with namespace will get the
        ghidra api and java namespace for you for free.
        """

        remote_main = self.bridge.remote_import("__main__")

        if namespace is not None:
            # we're going to need the all of __main__, so get it all in one hit
            remote_main._bridged_get_all()

        if self.interactive_mode:
            # if we're in headless mode (indicated by no state attribute for pythonRun or no tool for ghidra headless), we can't actually do interactive mode - we don't have access to a PluginTool
            if not hasattr(remote_main, 'state') or remote_main.state.getTool() is None:
                self.interactive_mode = False
                self.bridge.logger.warning(
                    "Disabling interactive mode - not supported when running against a headless Ghidra")
            else:
                # first, manually update all the current* values (this allows us to get the latest values, instead of what they were when the server started
                tool = remote_main.state.getTool()  # note: tool shouldn't change
                listing_panel = get_listing_panel(tool, remote_main.ghidra)
                locn = listing_panel.getProgramLocation()
                # set the values as overrides in the bridged object - this prevents them from being changed in the remote object
                remote_main._bridge_set_override(
                    "currentAddress", locn.getAddress())
                remote_main._bridge_set_override(
                    "currentProgram", listing_panel.getProgram())
                remote_main._bridge_set_override("currentLocation", locn)
                remote_main._bridge_set_override(
                    "currentSelection", listing_panel.getProgramSelection())
                remote_main._bridge_set_override(
                    "currentHighlight", listing_panel.getProgramHighlight())

                # next, keep a reference to this module for updating these addresses
                self.flat_api_modules_list.append(weakref.ref(remote_main))

                # next, overwrite getState with the getState_fix
                def getState_fix():
                    """ Used when in interactive mode - instead of calling the remote getState, 
                        relies on the fact that the current* variables are being updated and creates
                        a GhidraState based on them.

                        This avoids resetting the GUI to the original values in the remote getState
                    """
                    return remote_main.ghidra.app.script.GhidraState(tool, tool.getProject(), remote_main.currentProgram, remote_main.currentLocation, remote_main.currentSelection, remote_main.currentHighlight)
                remote_main._bridge_set_override("getState", getState_fix)

                # finally, install a listener for updates from the GUI events
                if self.interactive_listener is None:
                    def update_vars(currentProgram=None, currentLocation=None, currentSelection=None, currentHighlight=None):
                        """ For all the namespaces and modules we've returned, update the current* variables that have changed
                        """
                        # clear out any dead references
                        self.flat_api_modules_list = [
                            module for module in self.flat_api_modules_list if module() is not None]

                        update_list = [
                            module() for module in self.flat_api_modules_list]
                        for update in update_list:
                            # possible that a module might have been removed between the clear out and preparing the update list
                            if update is not None:
                                if currentProgram is not None:
                                    update.currentProgram = currentProgram
                                if currentLocation is not None:
                                    # match the order of updates in GhidraScript - location before address
                                    update.currentLocation = currentLocation
                                    update.currentAddress = currentLocation.getAddress()
                                if currentSelection is not None:
                                    update.currentSelection = currentSelection if not currentSelection.isEmpty() else None
                                if currentHighlight is not None:
                                    update.currentHighlight = currentHighlight if not currentHighlight.isEmpty() else None

                        # repeat the same for the namespace dictionaries, but also make sure we update the tracker so we know what to remove later
                        for update_dict in self.namespace_list:
                            if currentProgram is not None:
                                update_dict["currentProgram"] = currentProgram
                                update_dict[GHIDRA_BRIDGE_NAMESPACE_TRACK]["currentProgram"] = update_dict["currentProgram"]
                            if currentLocation is not None:
                                # match the order of updates in GhidraScript - location before address
                                update_dict["currentLocation"] = currentLocation
                                update_dict[GHIDRA_BRIDGE_NAMESPACE_TRACK]["currentLocation"] = update_dict["currentLocation"]
                                update_dict["currentAddress"] = currentLocation.getAddress(
                                )
                                update_dict[GHIDRA_BRIDGE_NAMESPACE_TRACK]["currentAddress"] = update_dict["currentAddress"]
                            if currentSelection is not None:
                                update_dict["currentSelection"] = currentSelection if not currentSelection.isEmpty(
                                ) else None
                                update_dict[GHIDRA_BRIDGE_NAMESPACE_TRACK]["currentSelection"] = update_dict["currentSelection"]
                            if currentHighlight is not None:
                                update_dict["currentHighlight"] = currentHighlight if not currentHighlight.isEmpty(
                                ) else None
                                update_dict[GHIDRA_BRIDGE_NAMESPACE_TRACK]["currentHighlight"] = update_dict["currentHighlight"]

                    # create the interactive listener to call our update_vars function (InteractiveListener defined in the GhidraBridgeServer class)
                    self.interactive_listener = remote_main.GhidraBridgeServer.InteractiveListener(
                        remote_main.state.getTool(), update_vars)

        if namespace is not None:
            # add a special var to the namespace to track what we add, so we can remove it easily later
            namespace[GHIDRA_BRIDGE_NAMESPACE_TRACK] = dict()

            # load in all the attrs from remote main, skipping the double underscores and avoiding overloading our own ghidra_bridge (and similar modules)
            try:
                for attr in set(remote_main._bridge_attrs + list(remote_main._bridge_overrides.keys())):
                    if not attr.startswith("__") and attr not in EXCLUDED_REMOTE_IMPORTS:
                        remote_attr = getattr(remote_main, attr)
                        namespace[attr] = remote_attr
                        # record what we added to the namespace
                        namespace[GHIDRA_BRIDGE_NAMESPACE_TRACK][attr] = remote_attr

                # overload isinstance with bridged_isinstance, so checking bridged objects are of bridged types will just work
                namespace["isinstance"] = bridge.bridged_isinstance
                namespace[GHIDRA_BRIDGE_NAMESPACE_TRACK]["isinstance"] = bridge.bridged_isinstance

                # overwrite help with our own function for using ghidra's help
                def ghidra_help(param=None):
                    """ Used when in interactive mode - calls through the bridge to call ghidra's help and capture the output, then print it locally """
                    if param is not None and not bridge._is_bridged_object(param):
                        # asking for help on something that isn't bridged - just use the original help
                        # make sure we have the real help, just in case we've overridden it already
                        builtin_help = None
                        try:
                            from builtins import help as builtin_help  # python3
                        except:
                            # try falling back to python2 syntax
                            from __builtin__ import help as builtin_help
                        builtin_help(param)
                    else:
                        # make a remote help call - either param is bridged, or no param (in which case, we'll get the default help for the GhidraScript API)
                        help_output = remote_main.GhidraBridgeServer.ghidra_help(
                            param)
                        pydoc.pager(help_output)

                namespace["help"] = ghidra_help
                namespace[GHIDRA_BRIDGE_NAMESPACE_TRACK]["help"] = ghidra_help

            except Exception:
                self.unload_flat_api(namespace)
                raise

            # if we're interactive, keep track of the namespace so we can update the current* values
            if self.interactive_mode:
                self.namespace_list.append(namespace)

        return remote_main

    def unload_flat_api(self, namespace=None):
        """ If get_flat_api was called with a namespace and loaded methods/fields into it, unload_flat_api will remove them.
            Note: if the values don't match what was loaded, we assume the caller has modified for their own reasons, and leave alone.
        """
        if namespace is None:
            if self.namespace is None:
                raise Exception(
                    "Bridge wasn't initialized with a namespace - need to specify the namespace you want to unload from")
            namespace = self.namespace

        if self.interactive_mode and namespace in self.namespace_list:
            self.namespace_list.remove(namespace)

        if GHIDRA_BRIDGE_NAMESPACE_TRACK in namespace:
            for key, value in namespace[GHIDRA_BRIDGE_NAMESPACE_TRACK].items():
                if key in namespace:
                    # we use "is", not ==, because we're checking it's the same object, not just that it matches
                    if namespace[key] is value:
                        del namespace[key]
        else:
            raise Exception(GHIDRA_BRIDGE_NAMESPACE_TRACK +
                            " not present in namespace - get_flat_api() didn't load into this namespace")

    def get_ghidra_api(self):
        """ get the ghidra api - `ghidra = bridge.get_ghidra_api()` equivalent to doing `import ghidra` in your script.
            Note that the module returned from get_flat_api() will also contain the ghidra module, so you may not need to call this.
        """
        return self.bridge.remote_import("ghidra")

    def get_java_api(self):
        """ get the java namespace - `java = bridge.get_java_api()` equivalent to doing `import java` in your script.
            Note that the module returned from get_flat_api() will also contain the java module, so you may not need to call this.
        """
        return self.bridge.remote_import("java")

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.namespace is not None:
            self.unload_flat_api(self.namespace)

        if self.interactive_listener is not None:
            self.interactive_listener.stop_listening()
