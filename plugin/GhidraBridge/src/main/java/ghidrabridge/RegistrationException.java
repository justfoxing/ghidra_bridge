package ghidrabridge;

/**
 * Indicates an issue with the python bridge registering with the plugin
 */
public class RegistrationException extends Exception {
	public RegistrationException(String message) {
		super(message);
	}
}
