package ghidrabridge;

import java.io.FileNotFoundException;
import java.io.PrintWriter;

import docking.action.DockingAction;
import generic.jar.ResourceFile;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.python.PythonScript;
import ghidra.python.PythonScriptProvider;
import ghidra.util.task.TaskMonitor;

public class BridgeControl {

	// bridge configuration info and getters for python to access it
		private static int serverPort = 0x4768; // port for the server to listen on
		private static String serverHost = "127.0.0.1"; // address for the server to listen on - default is 127.0.0.1 to minimise the likelihood of listening on the network
		private static double responseTimeout = 2.0; // seconds to wait for a response from the other side before throwing an exception
		  
		public static int getServerPort()
		{
			return serverPort;
		}
		
		public static String getServerHost()
		{
			return serverHost;
		}
		
		public static double getResponseTimeout()
		{
			return responseTimeout;
		}
	
	public enum BridgeState {
		STOPPED, // completely stopped, safe to start
		STARTING, // preparing to start - wait until running before stopping
		RUNNING, // running! can be safely stopped
		STOPPING // shutting down - wait until stopped before restarting
	}

	private static BridgeState bridgeState = BridgeState.STOPPED;
	private static String BRIDGE_SCRIPT_PATH = "ghidra_scripts/ghidra_bridge_server.py";

	private static BridgeThread bridgeThread;

	/*
	 * Called by python ghidra_bridge_server to register a callback so we can
	 * shutdown the bridge cleanly.
	 */
	public static void registerShutdownCallback(IShutdownCallback callback) throws RegistrationException {
		System.out.println("hey, registering");
		synchronized (bridgeState) {
			// expect bridgestate to be starting
			if (BridgeState.STARTING == bridgeState) {
				// expect to have a bridge thread
				if (bridgeThread == null) {
					throw new RegistrationException("No BridgeThread available");
				}

				bridgeThread.setShutdownCallback(callback);
				// bridge is now up and running!
				bridgeState = BridgeState.RUNNING;
				System.out.println("hey, registered" + callback.toString());
			} else if (BridgeState.STOPPING == bridgeState || BridgeState.STOPPED == bridgeState) {
				throw new RegistrationException("Bridge shutdown already requested. Not registering");
			} else {
				// uh oh, can't register while the bridge is still running
				throw new RegistrationException(
						"Can't register when GhidraBridge already running. Something's gone wrong. Restart everything!");
			}
		}
	}

	private static void startBridgeInThread(ProgramPlugin plugin, DockingAction toggleAction) {
		PluginTool tool = plugin.getTool();
		ConsoleService console = tool.getService(ConsoleService.class);
		PrintWriter stdErr = console.getStdErr();

		// expect bridgestate to be starting
		if (BridgeState.STARTING == bridgeState) {
			// We use the python script provider and manually run a python script instead of
			// using GhidraScriptService to avoid the pop-up box and transaction locking
			PythonScriptProvider scriptProvider = new PythonScriptProvider();
			ResourceFile scriptFile = null;

			try {
				scriptFile = Application.getModuleFile("GhidraBridge", BRIDGE_SCRIPT_PATH);

				// generate the initial state for the script
				GhidraState state = new GhidraState(tool, tool.getProject(), plugin.getCurrentProgram(),
						plugin.getProgramLocation(), plugin.getProgramSelection(), plugin.getProgramHighlight());

				try {
					PrintWriter stdOut = console.getStdOut();
					PythonScript script = (PythonScript) scriptProvider.getScriptInstance(scriptFile, stdOut);

					script.set(state, TaskMonitor.DUMMY, stdOut);

					bridgeThread = new BridgeThread(script);

					// start the bridge!
					bridgeThread.startAndWaitForRegistration();

					toggleAction.getMenuBarData().setMenuItemName("Stop");

				} catch (ClassNotFoundException | InstantiationException | IllegalAccessException
						| RegistrationException e) {
					e.printStackTrace();
					stdErr.println("Error starting GhidraBridge!");
				}

			} catch (FileNotFoundException e) {
				stdErr.println("Couldn't find " + BRIDGE_SCRIPT_PATH + ", can't start GhidraBridge!");
			}
		} else {
			stdErr.println("GhidraBridge in unexpected state when trying to start. Restart everything!");
		}
	}

	private static void stopBridgeInThread(ProgramPlugin plugin, DockingAction toggleAction) {
		ConsoleService console = plugin.getTool().getService(ConsoleService.class);

		synchronized (bridgeState) {
			// expect bridgestate to be stopping
			if (BridgeState.STOPPING == bridgeState) {
				// expect to have a bridge thread
				if (bridgeThread == null) {
					console.getStdErr().println("No BridgeThread available - something's weird.");
				} else {

					// shut it down!
					try {
						bridgeThread.shutdown();
					} catch (InterruptedException e) {
						console.getStdErr().println("Interrupted while waiting for GhidraBridge to shutdown");
					}

					console.getStdErr().println("shutdown called and returned");
					bridgeState = BridgeState.STOPPED;
					bridgeThread = null;
					toggleAction.getMenuBarData().setMenuItemName("Start");
				}
			}
		}
	}

	/**
	 * Get off the main UI thread and start or stop the bridge
	 * 
	 * If bridge is in starting/running -> set to stopping. If bridge is in stopped
	 * -> set to starting. If bridge is in stopping -> error, wait.
	 * 
	 * Returns only once thread has been started and bridge state has been altered,
	 * or if there's an error
	 */
	public static void toggleBridge(ProgramPlugin plugin, DockingAction toggleAction) {
		ConsoleService console = plugin.getTool().getService(ConsoleService.class);
		PrintWriter stdErr = console.getStdErr();

		synchronized (bridgeState) {
			if ((BridgeState.STARTING == bridgeState) || (BridgeState.RUNNING == bridgeState)) {
				bridgeState = BridgeState.STOPPING;
				new Thread(new Runnable() {
					@Override
					public void run() {
						stopBridgeInThread(plugin, toggleAction);
					}
				}).start();
			} else if (BridgeState.STOPPING == bridgeState) {
				stdErr.println("GhidraBridge is stopping. Please wait.");
			} else if (BridgeState.STOPPED == bridgeState) {
				bridgeState = BridgeState.STARTING;
				new Thread(new Runnable() {
					@Override
					public void run() {
						startBridgeInThread(plugin, toggleAction);
					}
				}).start();
			}
		}
	}

	// TODO race condition: STARTING->someone requests shutdown and we move to
	// STOPPING->bridgeThread.shutdown() waiting for join XXX blocks python thread
	// trying to register

	private static void restartBridgeInThread(ProgramPlugin plugin, DockingAction toggleAction) {
		ConsoleService console = plugin.getTool().getService(ConsoleService.class);

		BridgeThread waitOnStoppingThread = null;
		synchronized (bridgeState) {
			if ((BridgeState.STARTING == bridgeState) || (BridgeState.RUNNING == bridgeState)) {
				bridgeState = BridgeState.STOPPING;
				stopBridgeInThread(plugin, toggleAction);
			}
			// special case - someone already stopping the bridge means we want to wait on
			// the thread, and need to release the lock
			else if (BridgeState.STOPPING == bridgeState) {
				if (bridgeThread == null) {
					console.getStdErr().println("No BridgeThread available but state is stopping - something's weird.");
				} else {
					waitOnStoppingThread = bridgeThread;
				}
			}
		}

		if (null != waitOnStoppingThread) {
			try {
				waitOnStoppingThread.join();
			} catch (InterruptedException e) {
				console.getStdErr().println("Restart interrupted while waiting for bridge to stop.");
				return;
			}
		}

		synchronized (bridgeState) {
			// we expect to be stopped now
			if (BridgeState.STOPPED == bridgeState) {
				bridgeState = BridgeState.STARTING;
				startBridgeInThread(plugin, toggleAction);
			} else {
				console.getStdErr().println("Trying to restart, but bridge didn't end up stopped");
			}
		}
	}

	/**
	 * Get off the main UI thread and trigger the bridge to stop then restart
	 */
	public static void restartBridge(ProgramPlugin plugin, DockingAction toggleAction) {
		new Thread(new Runnable() {
			@Override
			public void run() {
				restartBridgeInThread(plugin, toggleAction);
			}
		}).start();
	}
}
