package am.ik.webhook;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

@FunctionalInterface
public interface WebhookSigner {

	default String sign(String payload, Encoder encoder) {
		return this.sign(Objects.requireNonNull(payload, "'payload' must not be null").getBytes(StandardCharsets.UTF_8),
				encoder);
	}

	String sign(byte[] payload, Encoder encoder);

	static WebhookSigner hmacSha1(String secret) {
		return new HmacWebhookSigner("SHA1", secret);
	}

	static WebhookSigner hmacSha256(String secret) {
		return new HmacWebhookSigner("SHA256", secret);
	}

	static WebhookSigner hmacSha512(String secret) {
		return new HmacWebhookSigner("SHA512", secret);
	}

	@FunctionalInterface
	interface Encoder {

		String encode(byte[] data);

		Encoder HEX = Hex::encodeHex;

		Encoder BASE64 = data -> Base64.getEncoder().encodeToString(data);

	}

}
