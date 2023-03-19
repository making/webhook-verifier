package am.ik.webhook;

import java.util.logging.Logger;

public final class WebhookVerifier {

	private final Logger log = Logger.getLogger(WebhookVerifier.class.getName());

	private final WebhookSigner signer;

	private final WebhookEncoder encoder;

	public WebhookVerifier(WebhookSigner signer, WebhookEncoder encoder) {
		this.signer = signer;
		this.encoder = encoder;
	}

	public void verify(String payload, String signature) {
		String computedSignature = this.sign(payload);
		if (!computedSignature.equalsIgnoreCase(signature)) {
			log.warning(() -> "Failed to verify payload (payload=%s, signature=%s)".formatted(payload, signature));
			throw new WebhookAuthenticationException(signature);
		}
	}

	public String sign(String payload) {
		return this.signer.sign(payload, this.encoder);
	}

	public static WebhookVerifier gitHubSha1(String secret) {
		return new WebhookVerifier(WebhookSigner.hmacSha1(secret), WebhookEncoder.HEX);
	}

	public static WebhookVerifier gitHubSha256(String secret) {
		return new WebhookVerifier(WebhookSigner.hmacSha256(secret), WebhookEncoder.HEX);
	}

}
