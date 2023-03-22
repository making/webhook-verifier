package am.ik.webhook.spring;

import java.nio.charset.StandardCharsets;

import am.ik.webhook.WebhookAuthenticationException;
import am.ik.webhook.WebhookHttpHeaders;
import am.ik.webhook.annotation.WebhookPayload;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class WebhookVerifierRequestBodyAdviceTest {

	MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new TestController())
		.setControllerAdvice(WebhookVerifierRequestBodyAdvice.githubSha256("my_little_secret"))
		.build();

	@Test
	void test_400() throws Exception {
		final MvcResult mvcResult = this.mockMvc
			.perform(post("/string").contentType(MediaType.APPLICATION_JSON).content("{ \"id\": \"realtime_update\" }"))
			.andExpect(status().isBadRequest())
			.andReturn();
		final Exception resolvedException = mvcResult.getResolvedException();
		assertThat(resolvedException).isInstanceOf(ResponseStatusException.class);
		assertThat(resolvedException).isNotNull();
		assertThat(((ResponseStatusException) resolvedException).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

	}

	@Test
	void test_403() throws Exception {
		final MvcResult mvcResult = this.mockMvc
			.perform(post("/string").contentType(MediaType.APPLICATION_JSON)
				.header(WebhookHttpHeaders.X_HUB_SIGNATURE_256,
						"sha256=ad4327fdb7670348eed766ee96c4164809cb49e761581fd4678629b31bbee362")
				.content("{ \"id\": \"realtime_update\" }"))
			.andExpect(status().isForbidden())
			.andReturn();
		final Exception resolvedException = mvcResult.getResolvedException();
		assertThat(resolvedException).isInstanceOf(ResponseStatusException.class);
		assertThat(resolvedException).isNotNull();
		assertThat(((ResponseStatusException) resolvedException).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
		final Throwable cause = resolvedException.getCause();
		assertThat(cause).isInstanceOf(WebhookAuthenticationException.class);
		assertThat(cause).isNotNull();
		assertThat(cause.getMessage()).isEqualTo(
				"Could not verify signature: 'sha256=ad4327fdb7670348eed766ee96c4164809cb49e761581fd4678629b31bbee362'");
	}

	@ParameterizedTest
	@CsvSource({ "/string", "/bytes" })
	void test_200(String path) throws Exception {
		this.mockMvc
			.perform(post(path).contentType(MediaType.APPLICATION_JSON)
				.header(WebhookHttpHeaders.X_HUB_SIGNATURE_256,
						"sha256=2bee603b1bd2b873912ee43469a3b4a377ad70e7f64cbd58ccdbc67eb9a1b37f")
				.content("{ \"id\": \"realtime_update\" }"))
			.andExpect(status().isOk())
			.andExpect(content().string("OK: { \"id\": \"realtime_update\" }"));
	}

	@RestController
	static class TestController {

		@PostMapping(path = "/string")
		public String string(@WebhookPayload @RequestBody String payload) {
			return "OK: " + payload;
		}

		@PostMapping(path = "/bytes")
		public String bytes(@WebhookPayload @RequestBody byte[] payload) {
			return "OK: " + new String(payload, StandardCharsets.UTF_8);
		}

	}

}