package ghidrabridge;

public class BridgeState {

	public enum Status {
		STOPPED, 	// completely stopped, safe to start
		STARTING,	// preparing to start - wait until running before stopping
		RUNNING,	// running! can be safely stopped
		STOPPING	// shutting down - wait until stopped before restarting
	}
	
	private static Status bridgeStatus = Status.STOPPED;

	/**
	 * Checks the status of the bridge to see if it can be started (e.g., in STOPPED [or STOPPING if wait is true])
	 * @param markAsStarting if true, and bridge can be started, will change the status to STARTING - requires caller to start the bridge
	 * @param wait if true, will wait for STOPPING status to become STOPPED
	 * @return true if the bridge needs to be started
	 */
	public static synchronized boolean canBridgeBeStarted(boolean markAsStarting, boolean wait)
	{  
		if ((bridgeStatus == Status.STOPPING) && wait) {
			// wait for a timeout period
			try {
				Thread.sleep(1);
			} catch (InterruptedException e) {
				// accept interruption and ignore
			}
		}
		
		if (bridgeStatus == Status.STOPPED){
			if (markAsStarting)
			{
				bridgeStatus = Status.STARTING;
			}
			
			return true;
		}
		
		// bridge is not stopped - don't start it
		return false;
	}
	
	/**
	 * Checks the status of the bridge to see if it can be stopped (e.g., in RUNNING [or STARTING if wait is true])
	 * @param markAsStopping if true, and bridge can be stopped, will change the status to STOPPED - requires caller to stop the bridge
	 * @param wait if true, will wait for STARTING status to become RUNNING
	 * @return true if the bridge needs to be started
	 */
	public static synchronized boolean canBridgeBeStopped(boolean markAsStopping, boolean wait)
	{  
		if ((bridgeStatus == Status.STARTING) && wait) {
			// wait for a timeout period
			try {
				Thread.sleep(1);
			} catch (InterruptedException e) {
				// accept interruption and ignore
			}
		}
		
		if (bridgeStatus == Status.RUNNING){
			if (markAsStopping)
			{
				bridgeStatus = Status.STOPPING;
			}
			  
			return true;
		}
		
		// bridge is not started - don't stop it
		return false;
	}
	
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
	
	// callback for shutting down the bridge - if not null, the bridge is running
	private static IShutdownCallback shutdownCallback = null;
	public static boolean isBridgeRunning()
	{
		return shutdownCallback != null;
	}
	
	/*
	 * Called by python ghidra_bridge_server to register a callback so we can shutdown the bridge cleanly.
	 * 
	 * Note that this isn't synchronized - if somehow multiple bridges get started at the same time, we have
	 * a race condition. However, the paths to this from Java _are_ all synchronized, so we shouldn't end up
	 * in that situation unless someone's doing something unexpected.
	 * 
	 * We don't synchronize this, because we want the python script to be able to do the registration before
	 * startBridgeThread() finishes, so we can check that it has started correctly.
	 */
	public static void registerShutdownCallback(IShutdownCallback callback) throws RegistrationException
	{
		System.out.println("hey, registering");
		if (isBridgeRunning())
		{
			// uh oh, can't register while the bridge is still running
			throw new RegistrationException("I thought GhidraBridge was already running. Something's gone wrong. Restart everything!");
		}
		
		shutdownCallback = callback;
		
		System.out.println("hey, registered" + shutdownCallback.toString());
	}


}
