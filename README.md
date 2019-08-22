Ghidra Bridge
=====================
Ghidra is great, and I like scripting as much of my RE as possible. But Ghidra's Python scripting is based on Jython, which isn't in a great state these days (not that IDA's Python environment is any better...). Installing new packages is a hassle, if they can even run in a Jython environment, and it's only going to get worse as Python 2 slowly gets turned off.

So Ghidra Bridge is an effort to sidestep that problem - instead of being stuck in Jython, set up an RPC proxy for Python objects, so we can call into Ghidra/Jython-land to get the data we need, then bring it back to a more up-to-date Python with all the packages you need to do your work. 

The aim is to be as transparent as possible, so once you're set up, you shouldn't need to know if an object is local or from the remote Ghidra - the bridge should seamlessly handle getting/setting/calling against it.

How to use for Ghidra
======================

## Start Server
### CodeBrowser Context

For a better interactive shell like IPython or if you need Python 3 libraries in your interactive environment you can start the bridge in the context of an interactive GUI session.

1. Add the path to the ghidra_bridge directory as a script directory in the Ghidra Script Manager (the "3 line" button left of the big red "plus" at the top of the Script Manager)
2. Run ghidra_bridge_server.py from the Ghidra Script Manager

### Headless Analysis Context

You can run Ghidra Bridge as a post analysis script for a headless analysis and then run some further analysis from the client.
```
$ghidraRoot/support/analyzeHeadless ghidra-project -import /bin/ls  -scriptPath ghidra_bridge/ -postscript ghidra_bridge/ghidra_bridge_server.py
```
### pythonRun Context

You can start the bridge in an environment without any program loaded, for example if you want to access some API like the DataTypeManager that doesn't require a program being analyzed

```
$ghidraRoot/support/pythonRun ghidra_bridge/ghidra_bridge_server.py
```

## Setup Client

1. Install ghidra_bridge in the client python environment (packaged at https://pypi.org/project/ghidra-bridge/):
```
pip install ghidra_bridge
```

2. From the client python:
```python
import ghidra_bridge
with ghidra_bridge.GhidraBridge(namespace=globals()):
    print(getState().getCurrentAddress().getOffset())
    ghidra.program.model.data.DataUtilities.isUndefinedData(currentProgram, currentAddress)
```
or
```python
import ghidra_bridge
b = ghidra_bridge.GhidraBridge(namespace=globals()) # creates the bridge and loads the flat API into the global namespace
print(getState().getCurrentAddress().getOffset())
# ghidra module implicitly loaded at the same time as the flat API
ghidra.program.model.data.DataUtilities.isUndefinedData(currentProgram, currentAddress)
```

Security warning
=====================
Be aware that when running, a Ghidra Bridge server effectively provides code execution as a service. If an attacker is able to talk to the port Ghidra Bridge is running on, they can trivially gain execution with the privileges Ghidra is run with. 

Also be aware that the protocol used for sending and receiving Ghidra Bridge messages is unencrypted and unverified - a person-in-the-middle attack would allow complete control of the commands and responses, again providing trivial code execution on the server (and with a little more work, on the client). 

By default, the Ghidra Bridge server only listens on localhost to slightly reduce the attack surface. Only listen on external network addresses if you're confident you're on a network where it is safe to do so. Additionally, it is still possible for attackers to send messages to localhost (e.g., via malicious javascript in the browser, or by exploiting a different process and attacking Ghidra Bridge to elevate privileges). You can mitigate this risk by running Ghidra Bridge from a Ghidra server with reduced permissions (a non-admin user, or inside a container), by only running it when needed, or by running on non-network connected systems.

Remote eval
=====================
Ghidra Bridge is designed to be transparent, to allow easy porting of non-bridged scripts without too many changes. However, if you're happy to make changes, and you run into slowdowns caused by running lots of remote queries (e.g., something like `for function in currentProgram.getFunctionManager().getFunctions(): doSomething()` can be quite slow with a large number of functions as each function will result in a message across the bridge), you can make use of the bridge.remote_eval() function to ask for the result to be evaluated on the bridge server all at once, which will require only a single message roundtrip.

The following example demonstrates getting a list of all the names of all the functions in a binary:
```python
import ghidra_bridge 
b = ghidra_bridge.GhidraBridge(namespace=globals())
name_list = b.bridge.remote_eval("[ f.getName() for f in currentProgram.getFunctionManager().getFunctions(True)]")
```

If your evaluation is going to take some time, you might need to use the timeout_override argument to increase how long the bridge will wait before deciding things have gone wrong.

If you need to supply an argument for the remote evaluation, you can provide arbitrary keyword arguments to the remote_eval function which will be passed into the evaluation context as local variables. The following argument passes in a function:
```python
import ghidra_bridge 
b = ghidra_bridge.GhidraBridge(namespace=globals())
func = currentProgram.getFunctionManager().getFunctions(True).next()
mnemonics = b.bridge.remote_eval("[ i.getMnemonicString() for i in currentProgram.getListing().getInstructions(f.getBody(), True)]", f=func)
```
As a simplification, note also that the evaluation context has the same globals loaded into the \_\_main\_\_ of the script that started the server - in the case of the Ghidra Bridge server, these include the flat API and values such as the currentProgram.

Interactive mode
=====================
Normally, Ghidra scripts get an instance of the Ghidra state and current\* variables (currentProgram, currentAddress, etc) when first started, and it doesn't update while the script runs. However, if you run the Ghidra Python interpreter, that updates its state with every command, so that currentAddress always matches the GUI.

To reflect this, GhidraBridge will automatically attempt to determine if you're running the client in an interactive environment (e.g., the Python interpreter, iPython) or just from a script. If it's an interactive environment, it'll register an event listener with Ghidra and perform some dubious behind-the-scenes shenanigans to make sure that the state is updated with GUI changes to behave like the Ghidra Python interpreter.  It'll also replace `help()` with one that reaches out to use Ghidra's help across the bridge if you give it a bridged object.

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
* Thanks also to @fmagin for remote_eval, allowing faster remote processing for batch queries!
