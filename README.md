# webhook-verifier
A webhook verifier for Java


```xml
<dependency>
  <groupId>am.ik.webhook</groupId>
  <artifactId>webhook-verifier</artifactId>
  <version>0.1.2</version>
</dependency>
```

### Basic Usage

```java
import am.ik.webhook.HmacWebhookSigner;
import am.ik.webhook.WebhookHttpHeaders;
import am.ik.webhook.WebhookSigner;
import am.ik.webhook.WebhookVerifier;

// for the webhook from Github
WebhookVerifier verifier = new WebhookVerifier(new HmacWebhookSigner("SHA256", "mysecret"), WebhookSigner.Encoder.HEX);
// shortcut version 
// WebhookVerifier verifier = WebhookVerifier.gitHubSha256("mysecret");

String payload = /* read the request body as String or byte[] */ ;
String signature = request.getHeader(WebhookHttpHeaders.X_HUB_SIGNATURE_256);
verifier.verify(payload, signature); // throws WebhookAuthenticationException if the verification fails
```

### Spring Integration

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WebConfig {
	@Bean
	public WebhookVerifierRequestBodyAdvice webhookVerifierRequestBodyAdvice() {
		WebhookVerifierRequestBodyAdvice.githubSha256("mysecret");
	}
}
```

```java
import am.ik.webhook.annotation.WebhookPayload;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

public class WebhookController {
	@PostMapping(path = "/webhook")
	public String webhook(@WebhookPayload @RequestBody String payload /* must be String or byte[] */) {
		// ...
		return "OK";
	}
}
```

### Required

* Java 17+

### License

Licensed under the Apache License, Version 2.0.