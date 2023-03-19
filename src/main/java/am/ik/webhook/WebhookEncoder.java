package am.ik.webhook;

import java.util.Base64;

@FunctionalInterface
public interface WebhookEncoder {

	String encode(byte[] data);

	WebhookEncoder HEX = Hex::encodeHex;

	WebhookEncoder BASE64 = data -> Base64.getEncoder().encodeToString(data);

}
