from . import bridge

""" Use this list to exclude modules loaded on the remote side from being loaded into our namespace.
This prevents the ghidra_bridge imported by ghidra_bridge_server being loaded over the local ghidra_bridge and causing issues.
You probably only want this for stuff imported by the ghidra_bridge_server script that might conflict on the local side.
"""
EXCLUDED_REMOTE_IMPORTS = ["logging", "subprocess", "ghidra_bridge"]

GHIDRA_BRIDGE_NAMESPACE_TRACK = "__ghidra_bridge_namespace_track__"


class GhidraBridge():
    def __init__(self, server_host="127.0.0.1", server_port=0, connect_to_host=bridge.DEFAULT_HOST, connect_to_port=bridge.DEFAULT_SERVER_PORT, start_in_background=True, loglevel=None, namespace=None):
        """ Set up a bridge. Default settings are for a client - connect to the default ghidra bridge server, set up a listening server on a random
        port, and start it in a background thread. For a ghidra bridge server, specify the server_port, set connect_to_* to None and set
        start_in_background to False

        If namespace is specified (e.g., locals() or globals()), automatically calls get_flat_api() with that namespace. Note that this requires
        connect_to_host and connect_to_port to not be None
        """
        self.bridge = bridge.Bridge(server_host=server_host, server_port=server_port,
                                    connect_to_host=connect_to_host, connect_to_port=connect_to_port,
                                    start_in_background=start_in_background, loglevel=loglevel)

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

        Note that the ghidra package is always loaded into the remote script's side, so get_flat_api with namespace will get the ghidra api for
        you for free.
        """

        remote_main = self.bridge.remote_import("__main__")

        if namespace is not None:
            # add a special var to the namespace to track what we add, so we can remove it easily later
            namespace[GHIDRA_BRIDGE_NAMESPACE_TRACK] = dict()

            # load in all the attrs from remote main, skipping the double underscores and avoiding overloading our own ghidra_bridge
            for attr in remote_main._bridge_attrs:
                if not attr.startswith("__") and attr not in EXCLUDED_REMOTE_IMPORTS:
                    remote_attr = getattr(remote_main, attr)
                    namespace[attr] = remote_attr
                    # record what we added to the namespace
                    namespace[GHIDRA_BRIDGE_NAMESPACE_TRACK][attr] = remote_attr

        return remote_main

    def unload_flat_api(self, namespace):
        """ If get_flat_api was called with a namespace and loaded methods/fields into it, unload_flat_api will remove them.
            Note: if the values don't match what was loaded, we assume the caller has modified for their own reasons, and leave alone.
        """
        if GHIDRA_BRIDGE_NAMESPACE_TRACK in namespace:
            for key, value in namespace[GHIDRA_BRIDGE_NAMESPACE_TRACK].items():
                if key in namespace:
                    if namespace[key] == value:
                        del namespace[key]
        else:
            raise Exception(GHIDRA_BRIDGE_NAMESPACE_TRACK +
                            " not present in namespace - get_flat_api() didn't load into this namespace")

    def get_ghidra_api(self):
        """ get the ghidra api - `ghidra = bridge.get_ghidra_api()` equivalent to doing `import ghidra` in your script.
            Note that the module returned from get_flat_api() will also contain the ghidra module, so you may not need to call this.
        """
        return self.bridge.remote_import("ghidra")

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.namespace is not None:
            self.unload_flat_api(self.namespace)
