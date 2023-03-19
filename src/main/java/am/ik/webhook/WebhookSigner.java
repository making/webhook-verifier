package am.ik.webhook;

@FunctionalInterface
public interface WebhookSigner {

	String sign(String payload, WebhookEncoder encoder);

	static WebhookSigner hmacSha1(String secret) {
		return new HmacWebhookSigner("SHA1", secret);
	}

	static WebhookSigner hmacSha256(String secret) {
		return new HmacWebhookSigner("SHA256", secret);
	}

	static WebhookSigner hmacSha512(String secret) {
		return new HmacWebhookSigner("SHA512", secret);
	}

}
