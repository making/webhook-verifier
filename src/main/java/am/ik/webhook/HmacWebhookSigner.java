package am.ik.webhook;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static java.util.Objects.requireNonNull;

public final class HmacWebhookSigner implements WebhookSigner {

	private final Mac hmac;

	private final String algorithmName;

	public HmacWebhookSigner(String algorithmName, String secret) {
		final String hmacAlgorithmName = "Hmac"
				+ requireNonNull(algorithmName, "'algorithmName' must not be null").toUpperCase();
		try {
			final SecretKeySpec signingKey = new SecretKeySpec(
					requireNonNull(secret, "'secret' must not be null").getBytes(), hmacAlgorithmName);
			this.hmac = Mac.getInstance(hmacAlgorithmName);
			this.hmac.init(signingKey);
		}
		catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new IllegalArgumentException(e);
		}
		this.algorithmName = algorithmName.toLowerCase();
	}

	@Override
	public String sign(String payload, Encoder encoder) {
		final byte[] sig = this.hmac.doFinal(requireNonNull(payload, "'payload' must not be null").getBytes());
		return this.algorithmName + "=" + encoder.encode(sig);
	}

}
