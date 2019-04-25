Ghidra Bridge
=====================
Ghidra is great, and I like scripting as much of my RE as possible. But Ghidra's Python scripting is based on Jython, which isn't in a great state these days (not that IDA's Python environment is any better...). Installing new packages is a hassle, if they can even run in a Jython environment, and it's only going to get worse as Python 2 slowly gets turned off.

So Ghidra Bridge is an effort to sidestep that problem - instead of being stuck in Jython, set up an RPC proxy for Python objects, so we can call into Ghidra/Jython-land to get the data we need, then bring it back to a more up-to-date Python with all the packages you need to do your work. 

The aim is to be as transparent as possible, so once you're set up, you shouldn't need to know if an object is local or from the remote Ghidra - the bridge should seamlessly handle getting/setting/calling against it.

How to use for Ghidra
======================

1. Add the path to the ghidra_bridge directory as a script directory in the Ghidra Script Manager (the "3 line" button left of the big red "plus" at the top of the Script Manager)
2. Run ghidra_bridge_server.py from the Ghidra Script Manager
3. From the client python environment:
```
import ghidra_bridge
b = ghidra_bridge.GhidraBridge(namespace=globals()) # creates the bridge and loads the flat API into the global namespace
print(getState().getCurrentAddress().getOffset())
# ghidra module implicitly loaded at the same time as the flat API
ghidra.program.model.data.DataUtilities.isUndefinedData(currentProgram, currentAddress)
```

or

```
import ghidra_bridge
with ghidra_bridge.GhidraBridge(namespace=globals()):
    print(getState().getCurrentAddress().getOffset())
    ghidra.program.model.data.DataUtilities.isUndefinedData(currentProgram, currentAddress)
```

How it works
=====================
bridge.py contains a py2/3 compatible python object RPC proxy. Each python environment being bridged sets up its own proxy, serving on one port, and communicating with the other environment on a different port. The bridge provides a handful of commands to carry out remote operations against python objects in the other environment.

A typical first step is remote_import() with a module to load in the target environment. This will make the RPC call to the remote bridge, which will load the module, then create a BridgeHandle to keep it alive and reference it across the bridge. It'll then return it to the local bridge, along with a list of the callable and non-callable attributes of the module.

At the local bridge, this will be deserialized into a BridgedObject, which overrides \__getattribute__ and \__setattr__ to catch any get/set to the attribute fields, and proxy them back across to the remote bridge, using the bridge handle reference so it knows which module (or other object) we're talking about.

The \__getattribute__ override also affects callables, so doing bridged_obj.func() actually returns a BridgedCallable object, which is then invoked (along with any args/kwargs in use). This packs the call parameters off to the remote bridge, which identifies the appropriate object and invokes the call against it, then returns the result.

The bridges are symmetric, so the local bridge is able to send references to local python objects to the remote bridge, and have them used over there, with interactions being sent back to the local bridge (e.g., providing a callback function as an argument should work).

Design principles
=====================
* Needs to be run in Ghidra/Jython 2.7 and Python 3
* Needs to be easy to install in Ghidra - no pip install, just add a single directory 
(these two requirements ruled out some of the more mature Python RPC projects I looked into)

Tested
=====================
Tested and working on Ghidra 9.0.2(Jython 2.7.1) <-> Python 3.6.5 on Windows

TODO
=====================
* Exceptions - pull traceback info in the exceptions we handle for pushing back
* Test on Linux
* Better transport/serialization (JSON/TCP just feels wrong)
* Packaging - would be nice to do pip install ghidra_bridge for the client-side.
* Keep stats of remote queries, so users can ID the parts of their scripts causing the most remote traffic for optimisation
* Examples
