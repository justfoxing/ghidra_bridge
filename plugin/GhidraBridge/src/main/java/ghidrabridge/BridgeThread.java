package ghidrabridge;

import ghidra.python.PythonScript;

public class BridgeThread extends Thread {

	PythonScript script;
	IShutdownCallback callback;

	public BridgeThread(PythonScript script) {
		this.script = script;
	}

	public void run() {
		script.run();
	}

	public void startAndWaitForRegistration() throws RegistrationException {

		// start the thread with the python script in it
		super.start();

		try {
			// wait until the bridge registers (or we're pretty sure it's not going to)
			for (int i = 0; i < 3; i++) { // give it three chances

				Thread.sleep(1000); // wait 1 second
				if (callback != null) {
					break; // cool, we're happy
				}
			}
		} catch (InterruptedException e) {
			// ignore
		}

		// check to see if the bridge has registered
		if (callback == null) {
			throw new RegistrationException("Error starting GhidraBridge! It didn't register after being started");
		}
	}

	public void setShutdownCallback(IShutdownCallback callback) {
		this.callback = callback;
	}

	public synchronized void shutdown() throws InterruptedException {
		if (callback != null) {
			callback.shutdown();

			// remove the shutdown callback to indicate the bridge has been stopped
			callback = null;

			// wait for this thread to return
			join();
		}
	}

}
