Ghidra Bridge
=====================
Ghidra is great, and I like scripting as much of my RE as possible. But Ghidra's Python scripting is based on Jython, which isn't in a great state these days (not that IDA's Python environment is any better...). Installing new packages is a hassle, if they can even run in a Jython environment, and it's only going to get worse as Python 2 slowly gets turned off.

So Ghidra Bridge is an effort to sidestep that problem - instead of being stuck in Jython, set up an RPC proxy for Python objects, so we can call into Ghidra/Jython-land to get the data we need, then bring it back to a more up-to-date Python with all the packages you need to do your work. 

The aim is to be as transparent as possible, so once you're set up, you shouldn't need to know if an object is local or from the remote Ghidra - the bridge should seamlessly handle getting/setting/calling against it.

How to use for Ghidra
======================

1. Add the path to the ghidra_bridge directory as a script directory in the Ghidra Script Manager (the "3 line" button left of the big red "plus" at the top of the Script Manager)
2. Run ghidra_bridge_server.py from the Ghidra Script Manager
3. Install ghidra_bridge in the client python environment (packaged at https://pypi.org/project/ghidra-bridge/):
```
pip install ghidra_bridge
```
4. From the client python:
```
import ghidra_bridge
with ghidra_bridge.GhidraBridge(namespace=globals()):
    print(getState().getCurrentAddress().getOffset())
    ghidra.program.model.data.DataUtilities.isUndefinedData(currentProgram, currentAddress)
```
or
```
import ghidra_bridge
b = ghidra_bridge.GhidraBridge(namespace=globals()) # creates the bridge and loads the flat API into the global namespace
print(getState().getCurrentAddress().getOffset())
# ghidra module implicitly loaded at the same time as the flat API
ghidra.program.model.data.DataUtilities.isUndefinedData(currentProgram, currentAddress)
```

Interactive mode
=====================
Normally, Ghidra scripts get an instance of the Ghidra state and current\* variables (currentProgram, currentAddress, etc) when first started, and it doesn't update while the script runs. However, if you run the Ghidra Python interpreter, that updates its state with every command, so that currentAddress always matches the GUI.

To reflect this, GhidraBridge will automatically attempt to determine if you're running the client in an interactive environment (e.g., the Python interpreter, iPython) or just from a script. If it's an interactive environment, it'll register an event listener with Ghidra and perform some dubious behind-the-scenes shenanigans to make sure that the state is updated with GUI changes to behave like the Ghidra Python interpreter. 

You shouldn't have to care about this, but if for some reason the auto-detection doesn't give you the result you need, you can specify the boolean interactive_mode argument when creating your client GhidraBridge to force it on or off as required.

How it works
=====================
bridge.py contains a py2/3 compatible python object RPC proxy. One python environment sets up a server on a port, which clients connect to. The bridge provides a handful of commands to carry out remote operations against python objects in the other environment.

A typical first step is remote_import() with a module to load in the target environment. This will make the RPC call to the remote bridge, which will load the module, then create a BridgeHandle to keep it alive and reference it across the bridge. It'll then return it to the local bridge, along with a list of the callable and non-callable attributes of the module.

At the local bridge, this will be deserialized into a BridgedObject, which overrides \_\_getattribute\_\_ and \_\_setattr\_\_ to catch any get/set to the attribute fields, and proxy them back across to the remote bridge, using the bridge handle reference so it knows which module (or other object) we're talking about.

The \_\_getattribute\_\_ override also affects callables, so doing bridged_obj.func() actually returns a BridgedCallable object, which is then invoked (along with any args/kwargs in use). This packs the call parameters off to the remote bridge, which identifies the appropriate object and invokes the call against it, then returns the result.

The bridges are symmetric, so the local bridge is able to send references to local python objects to the remote bridge, and have them used over there, with interactions being sent back to the local bridge (e.g., providing a callback function as an argument works).

Finally, there's a few other miscellaneous features to make life easier - bridged objects which are python iterators/iterables will behave as iterators/iterables in the remote environment, and bridged objects representing types can be inherited from to make your own subclasses of them (note that this will actually create the subclass in the remote environment - this is designed so you can create types to implement some of Ghidra's Java interfaces for callbacks/listeners/etc, so it was easier to make sure they behave if they're created in the Jython environment).

Design principles
=====================
* Needs to be run in Ghidra/Jython 2.7 and Python 3
* Needs to be easy to install in Ghidra - no pip install, just add a single directory 
(these two requirements ruled out some of the more mature Python RPC projects I looked into)

Tested
=====================
* Tested and working on Ghidra 9.0.4(Jython 2.7.1) <-> Python 3.7.3 on Windows
* Automatically tested on Ghidra 9.0(Jython 2.7.1) <-> Python 3.5.3 on Linux (bskaggs/ghidra docker image)

TODO
=====================
* Ghidra plugin for server control (cleaner start/stop, port selection, easy packaging/install)
* Handle server/client teardown cleanly
* Exceptions - pull traceback info in the exceptions we handle for pushing back
* Better transport/serialization (JSON/TCP just feels wrong)
* Keep stats of remote queries, so users can ID the parts of their scripts causing the most remote traffic for optimisation
* Examples
    * Jupyter notebook
* Better threadpool control (don't keep all threads around forever, allow some to die off)

Contributors
=====================
* Thx @fmagin for better iPython support, and much more useful reprs!
