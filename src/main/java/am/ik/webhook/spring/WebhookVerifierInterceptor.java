package am.ik.webhook.spring;

import java.nio.charset.StandardCharsets;

import am.ik.webhook.WebhookAuthenticationException;
import am.ik.webhook.WebhookVerifier;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.util.ContentCachingRequestWrapper;

import static am.ik.webhook.WebhookHttpHeaders.X_HUB_SIGNATURE;
import static am.ik.webhook.WebhookHttpHeaders.X_HUB_SIGNATURE_256;

public class WebhookVerifierInterceptor implements HandlerInterceptor {

	private final String signatureHeaderName;

	private final WebhookVerifier webhookVerifier;

	public static WebhookVerifierInterceptor githubSha256(String secret) {
		return new WebhookVerifierInterceptor(X_HUB_SIGNATURE_256, WebhookVerifier.gitHubSha256(secret));
	}

	public static WebhookVerifierInterceptor githubSha1(String secret) {
		return new WebhookVerifierInterceptor(X_HUB_SIGNATURE, WebhookVerifier.gitHubSha1(secret));
	}

	public WebhookVerifierInterceptor(String signatureHeaderName, WebhookVerifier webhookVerifier) {
		this.signatureHeaderName = signatureHeaderName;
		this.webhookVerifier = webhookVerifier;
	}

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {
		final String signature = request.getHeader(this.signatureHeaderName);
		if (!StringUtils.hasLength(signature)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
					"The signature header '%s' is missing or blank.".formatted(this.signatureHeaderName));
		}
		final ContentCachingRequestWrapper requestWrapper = request instanceof ContentCachingRequestWrapper
				? (ContentCachingRequestWrapper) request : new ContentCachingRequestWrapper(request);
		final ServletInputStream inputStream = requestWrapper.getInputStream();
		final String payload = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
		try {
			this.webhookVerifier.verify(payload, signature);
		}
		catch (WebhookAuthenticationException e) {
			throw new ResponseStatusException(HttpStatus.FORBIDDEN, e.getMessage(), e);
		}
		return true;
	}

}
