package am.ik.webhook;

/**
 * Exception raised when a github webhook message is received but its HMAC signature does
 * not match the one computed with the shared secret.
 */
public class WebhookAuthenticationException extends RuntimeException {

	public WebhookAuthenticationException(String actual) {
		super(String.format("Could not verify signature: '%s'", actual));
	}

}