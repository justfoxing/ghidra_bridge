package ghidrabridge;

import java.io.FileNotFoundException;
import java.io.PrintWriter;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import generic.jar.ResourceFile;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.framework.Application;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.python.PythonScript;
import ghidra.python.PythonScriptProvider;
import ghidra.util.task.TaskMonitor;
import ghidra.app.script.GhidraState;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(status = PluginStatus.UNSTABLE, 
	packageName = "GhidraBridge", 
	category = "GhidraBridge", 
	shortDescription = "Plugin short description goes here.", 
	description = "Plugin long description goes here.")
//@formatter:on
public class GhidraBridgePlugin extends ProgramPlugin {

	private static String BRIDGE_SCRIPT_PATH = "ghidra_scripts/ghidra_bridge_server.py";

	private PythonThread bridgeThread;

	private class PythonThread extends Thread {
		PythonScript script;

		public PythonThread(PythonScript script) {
			this.script = script;
		}

		public void run() {
			script.run();
		}
	}
	
	private void startBridgeInThread() {
		ConsoleService console = tool.getService(ConsoleService.class);
		PrintWriter stdErr = console.getStdErr();
		if (!BridgeState.isBridgeRunning())
		{
			// We use the python script provider and manually run a python script instead of using GhidraScriptService to avoid the pop-up box and transaction locking		
			PythonScriptProvider scriptProvider = new PythonScriptProvider();
			ResourceFile scriptFile = null;
	
			try {
				scriptFile = Application.getModuleFile("GhidraBridge", BRIDGE_SCRIPT_PATH);
			
				// generate the initial state for the script
				GhidraState state = new GhidraState(tool, tool.getProject(), getCurrentProgram(),
						getProgramLocation(), getProgramSelection(), getProgramHighlight()); 
					
				try {
					PrintWriter stdOut = console.getStdOut();
					PythonScript script = (PythonScript) scriptProvider.getScriptInstance(scriptFile, stdOut);
					
					script.set(state, TaskMonitor.DUMMY, stdOut);
					
					bridgeThread = new PythonThread(script);
					
					// start the bridge!
					bridgeThread.start();
					

					try {
						// wait until the bridge registers (or we're pretty sure it's not going to)
						for (int i = 0 ; i < 3; i++) { // give it three chances
							Thread.sleep(1000); // wait 1 second
							if (BridgeState.isBridgeRunning())
							{
								break; // cool, we're happy
							}
						}
					} catch (InterruptedException e) {
						stdErr.println("Interrupted while waiting for the bridge to register");
						e.printStackTrace();
					}
					
					// check to see if the bridge has registered
					if (!BridgeState.isBridgeRunning())
					{
						throw new RegistrationException("Error starting GhidraBridge! It didn't register after being started");
					}

				} catch (ClassNotFoundException | InstantiationException | IllegalAccessException | RegistrationException e) {
					e.printStackTrace();
					stdErr.println("Error starting GhidraBridge!");
				}
	
			} catch (FileNotFoundException e) {
				stdErr.println("Couldn't find " + BRIDGE_SCRIPT_PATH + ", can't start GhidraBridge!"); 
			}
		}
		else
		{
			stdErr.println("I thought GhidraBridge was already running. Something's gone wrong. Restart everything!");
		}
	}
	
	/**
	 * Get off the main UI thread and trigger the bridge to start
	 */
	private synchronized void startBridge()
	{		
		ConsoleService console = tool.getService(ConsoleService.class);
		PrintWriter stdErr = console.getStdErr();
		if (!BridgeState.isBridgeRunning())
		{
			new Thread(new Runnable() {
				@Override
				public void run() {
					startBridgeInThread();
				}
			}).start();
		}
		else
		{
			stdErr.println("I thought GhidraBridge was already running. Something's gone wrong. Restart everything!");
		}
	}
	
	private void stopBridgeInThread()
	{
		ConsoleService console1 = tool.getService(ConsoleService.class);
		console1.getStdErr().println("shutting down");
		if (BridgeState.shutdownCallback != null)
		{
			BridgeState.shutdownCallback.shutdown();
			console1.getStdErr().println("shutdown called and returned");
			// remove the shutdown callback to indicate the bridge has stopped
			BridgeState.shutdownCallback = null;
			
			// wait for the thread to return
			try {
				bridgeThread.join();
				bridgeThread = null;
				ConsoleService console = tool.getService(ConsoleService.class);
				console.getStdOut().println("Bridge stopped");
			} catch (InterruptedException e) {
				ConsoleService console = tool.getService(ConsoleService.class);
				console.getStdErr().println("Interrupted while waiting for GhidraBridge to stop");
				e.printStackTrace();
			}
		}
	}
	
	/**
	 * Get off the main UI thread and trigger the bridge to stop
	 */
	private synchronized void stopBridge()
	{		
		ConsoleService console = tool.getService(ConsoleService.class);
		PrintWriter stdErr = console.getStdErr();
		if (BridgeState.isBridgeRunning())
		{
			new Thread(new Runnable() {
				@Override
				public void run() {
					stopBridgeInThread();
				}
			}).start();
		}
		else
		{
			stdErr.println("Can't stop GhidraBridge - it's not running");
		}
	}

	/**
	 * Get off the main UI thread and trigger the bridge to stop then restart
	 */
	private synchronized void restartBridge()
	{		
		ConsoleService console = tool.getService(ConsoleService.class);
		PrintWriter stdErr = console.getStdErr();
		if (BridgeState.isBridgeRunning())
		{
			new Thread(new Runnable() {
				@Override
				public void run() {
					stopBridgeInThread();
				}
			}).start();
		}
		else
		{
			stdErr.println("Can't stop GhidraBridge - it's not running");
		}
	}
	
	
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	// Note: when developing/installing the plugin - you need to go into the tool and select the plugin from Configure->Unstable
	public GhidraBridgePlugin(PluginTool tool) {
		super(tool, true, true, true); // register for location, selection and highlight updates

		GhidraBridgePlugin plugin = this;
		DockingAction startStopAction = new DockingAction("Start/Stop GhidraBridge", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {

				synchronized (plugin) {
					if (!BridgeState.isBridgeRunning()) {
						startBridge();				
						this.getMenuBarData().setMenuItemName("Stop");
					} else {
						stopBridge();
						this.getMenuBarData().setMenuItemName("Start");
					}
				}
			}
		};
		// action.setToolBarData(new ToolBarData(Icons.STRONG_WARNING_ICON, "View")); -
		// tool bar is icon line just below file menu
		startStopAction.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_TOOLS, "GhidraBridge", "Start" }));
		tool.addAction(startStopAction);
		
		DockingAction restartAction = new DockingAction("Restart GhidraBridge", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {

				synchronized (plugin) {
					if(BridgeState.isBridgeRunning())
					{
						stopBridgeThread();
						startStopAction.getMenuBarData().setMenuItemName("Start");
					}
					
					if(!isBridgeRunning())
					{
						startBridgeThread();
						startStopAction.getMenuBarData().setMenuItemName("Stop");
					}
					else
					{
						ConsoleService console = tool.getService(ConsoleService.class);
						console.getStdErr().println("Couldn't stop GhidraBridge");
					}
				}
			}
		};
		restartAction.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_TOOLS, "GhidraBridge", "Restart" }));
		tool.addAction(restartAction);
	}

	@Override
	public void init() {
		super.init();		
	}

}
