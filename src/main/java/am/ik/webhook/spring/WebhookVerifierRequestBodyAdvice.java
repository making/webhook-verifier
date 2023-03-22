package am.ik.webhook.spring;

import java.lang.reflect.Type;
import java.util.function.Function;
import java.util.logging.Logger;

import am.ik.webhook.WebhookAuthenticationException;
import am.ik.webhook.WebhookHttpHeaders;
import am.ik.webhook.WebhookVerifier;
import am.ik.webhook.annotation.WebhookPayload;

import org.springframework.core.MethodParameter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;

@ControllerAdvice
public class WebhookVerifierRequestBodyAdvice extends RequestBodyAdviceAdapter {

	private final WebhookVerifier webhookVerifier;

	private final String signatureHeaderName;

	private final Logger log = Logger.getLogger(WebhookVerifierRequestBodyAdvice.class.getName());

	public static WebhookVerifierRequestBodyAdvice githubSha1(String secret) {
		return new WebhookVerifierRequestBodyAdvice(WebhookVerifier::gitHubSha1, secret,
				WebhookHttpHeaders.X_HUB_SIGNATURE);
	}

	public static WebhookVerifierRequestBodyAdvice githubSha256(String secret) {
		return new WebhookVerifierRequestBodyAdvice(WebhookVerifier::gitHubSha256, secret,
				WebhookHttpHeaders.X_HUB_SIGNATURE_256);
	}

	public WebhookVerifierRequestBodyAdvice(Function<String, WebhookVerifier> webhookVerifierFactory, String secret,
			String signatureHeaderName) {
		this.signatureHeaderName = signatureHeaderName;
		this.webhookVerifier = webhookVerifierFactory.apply(secret);
	}

	@Override
	public boolean supports(MethodParameter methodParameter, Type targetType,
			Class<? extends HttpMessageConverter<?>> converterType) {
		final boolean hasWebhookPayload = methodParameter.hasParameterAnnotation(WebhookPayload.class);
		if (hasWebhookPayload) {
			if (String.class.equals(targetType) || byte[].class.equals(targetType)) {
				return true;
			}
			else {
				log.warning(
						() -> "@WebhookPayload is found but the type (%s) is not supported. Only String and byte[] are supported as a payload type."
							.formatted(targetType));
			}
		}
		return false;
	}

	@Override
	public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType,
			Class<? extends HttpMessageConverter<?>> converterType) {
		final String signature = inputMessage.getHeaders().getFirst(this.signatureHeaderName);
		if (!StringUtils.hasLength(signature)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
					"The signature header '%s' is missing or blank.".formatted(this.signatureHeaderName));
		}
		log.info(() -> "Verify if the payload signature is '%s'".formatted(signature));
		try {
			if (body instanceof final String payload) {
				this.webhookVerifier.verify(payload, signature);
			}
			else if (body instanceof final byte[] payload) {
				this.webhookVerifier.verify(payload, signature);
			}
			else {
				throw new IllegalStateException("Only String and byte[] are supported as a payload type.");
			}
		}
		catch (WebhookAuthenticationException e) {
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, e.getMessage(), e);
		}
		return body;
	}

}
