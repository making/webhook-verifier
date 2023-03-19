package am.ik.webhook;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static am.ik.webhook.WebhookEncoder.BASE64;
import static am.ik.webhook.WebhookEncoder.HEX;
import static org.assertj.core.api.Assertions.assertThat;

class WebhookVerifierTest {

	/**
	 * <a href=
	 * "https://github.com/compwright/x-hub-signature/blob/master/src/XHubSignature.test.js">...</a>
	 * <a href=
	 * "https://github.com/McFoggy/xhub4j/blob/master/xhub4j-core/src/test/java/fr/brouillard/oss/security/xhub/TestXHub.java">...</a>
	 */
	@ParameterizedTest
	@CsvSource({ "random-signature-body,SHA1,my_little_secret,3dca279e731c97c38e3019a075dee9ebbd0a99f0",
			"The quick brown fox jumps over the lazy dog,SHA1,key,de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",
			"{ \"id\": \"realtime_update\" },SHA256,my_little_secret,2bee603b1bd2b873912ee43469a3b4a377ad70e7f64cbd58ccdbc67eb9a1b37f" })
	void signHex(String payload, String algorithm, String secret, String signature) throws Exception {
		final WebhookVerifier verifier = new WebhookVerifier(new HmacWebhookSigner(algorithm, secret), HEX);
		assertThat(verifier.sign(payload)).isEqualTo(algorithm.toLowerCase() + "=" + signature);
	}

	/**
	 * <a href=
	 * "https://github.com/McFoggy/xhub4j/blob/master/xhub4j-core/src/test/java/fr/brouillard/oss/security/xhub/TestXHub.java">...</a>
	 */
	@ParameterizedTest
	@CsvSource({ "foo,SHA1,qnscAdgRlkIhAUPY44oiexBKtQbGY0orf7OV1I50,+3h2gpjf4xcynjCGU5lbdMBwGOc=", })
	void signBase64(String payload, String algorithm, String secret, String signature) throws Exception {
		final WebhookVerifier verifier = new WebhookVerifier(new HmacWebhookSigner(algorithm, secret), BASE64);
		assertThat(verifier.sign(payload)).isEqualTo(algorithm.toLowerCase() + "=" + signature);
	}

	@Test
	void signWithGithubWebhook() {
		final String payload = "{\"zen\":\"Approachable is better than simple.\",\"hook_id\":405653791,\"hook\":{\"type\":\"Repository\",\"id\":405653791,\"name\":\"web\",\"active\":true,\"events\":[\"push\"],\"config\":{\"content_type\":\"json\",\"insecure_ssl\":\"0\",\"secret\":\"********\",\"url\":\"https://api.ik.am/webhook\"},\"updated_at\":\"2023-03-18T12:21:12Z\",\"created_at\":\"2023-03-18T12:21:12Z\",\"url\":\"https://api.github.com/repos/making/blog.ik.am/hooks/405653791\",\"test_url\":\"https://api.github.com/repos/making/blog.ik.am/hooks/405653791/test\",\"ping_url\":\"https://api.github.com/repos/making/blog.ik.am/hooks/405653791/pings\",\"deliveries_url\":\"https://api.github.com/repos/making/blog.ik.am/hooks/405653791/deliveries\",\"last_response\":{\"code\":null,\"status\":\"unused\",\"message\":null}},\"repository\":{\"id\":48331386,\"node_id\":\"MDEwOlJlcG9zaXRvcnk0ODMzMTM4Ng==\",\"name\":\"blog.ik.am\",\"full_name\":\"making/blog.ik.am\",\"private\":false,\"owner\":{\"login\":\"making\",\"id\":106908,\"node_id\":\"MDQ6VXNlcjEwNjkwOA==\",\"avatar_url\":\"https://avatars.githubusercontent.com/u/106908?v=4\",\"gravatar_id\":\"\",\"url\":\"https://api.github.com/users/making\",\"html_url\":\"https://github.com/making\",\"followers_url\":\"https://api.github.com/users/making/followers\",\"following_url\":\"https://api.github.com/users/making/following{/other_user}\",\"gists_url\":\"https://api.github.com/users/making/gists{/gist_id}\",\"starred_url\":\"https://api.github.com/users/making/starred{/owner}{/repo}\",\"subscriptions_url\":\"https://api.github.com/users/making/subscriptions\",\"organizations_url\":\"https://api.github.com/users/making/orgs\",\"repos_url\":\"https://api.github.com/users/making/repos\",\"events_url\":\"https://api.github.com/users/making/events{/privacy}\",\"received_events_url\":\"https://api.github.com/users/making/received_events\",\"type\":\"User\",\"site_admin\":false},\"html_url\":\"https://github.com/making/blog.ik.am\",\"description\":\"Blog Contents\",\"fork\":false,\"url\":\"https://api.github.com/repos/making/blog.ik.am\",\"forks_url\":\"https://api.github.com/repos/making/blog.ik.am/forks\",\"keys_url\":\"https://api.github.com/repos/making/blog.ik.am/keys{/key_id}\",\"collaborators_url\":\"https://api.github.com/repos/making/blog.ik.am/collaborators{/collaborator}\",\"teams_url\":\"https://api.github.com/repos/making/blog.ik.am/teams\",\"hooks_url\":\"https://api.github.com/repos/making/blog.ik.am/hooks\",\"issue_events_url\":\"https://api.github.com/repos/making/blog.ik.am/issues/events{/number}\",\"events_url\":\"https://api.github.com/repos/making/blog.ik.am/events\",\"assignees_url\":\"https://api.github.com/repos/making/blog.ik.am/assignees{/user}\",\"branches_url\":\"https://api.github.com/repos/making/blog.ik.am/branches{/branch}\",\"tags_url\":\"https://api.github.com/repos/making/blog.ik.am/tags\",\"blobs_url\":\"https://api.github.com/repos/making/blog.ik.am/git/blobs{/sha}\",\"git_tags_url\":\"https://api.github.com/repos/making/blog.ik.am/git/tags{/sha}\",\"git_refs_url\":\"https://api.github.com/repos/making/blog.ik.am/git/refs{/sha}\",\"trees_url\":\"https://api.github.com/repos/making/blog.ik.am/git/trees{/sha}\",\"statuses_url\":\"https://api.github.com/repos/making/blog.ik.am/statuses/{sha}\",\"languages_url\":\"https://api.github.com/repos/making/blog.ik.am/languages\",\"stargazers_url\":\"https://api.github.com/repos/making/blog.ik.am/stargazers\",\"contributors_url\":\"https://api.github.com/repos/making/blog.ik.am/contributors\",\"subscribers_url\":\"https://api.github.com/repos/making/blog.ik.am/subscribers\",\"subscription_url\":\"https://api.github.com/repos/making/blog.ik.am/subscription\",\"commits_url\":\"https://api.github.com/repos/making/blog.ik.am/commits{/sha}\",\"git_commits_url\":\"https://api.github.com/repos/making/blog.ik.am/git/commits{/sha}\",\"comments_url\":\"https://api.github.com/repos/making/blog.ik.am/comments{/number}\",\"issue_comment_url\":\"https://api.github.com/repos/making/blog.ik.am/issues/comments{/number}\",\"contents_url\":\"https://api.github.com/repos/making/blog.ik.am/contents/{+path}\",\"compare_url\":\"https://api.github.com/repos/making/blog.ik.am/compare/{base}...{head}\",\"merges_url\":\"https://api.github.com/repos/making/blog.ik.am/merges\",\"archive_url\":\"https://api.github.com/repos/making/blog.ik.am/{archive_format}{/ref}\",\"downloads_url\":\"https://api.github.com/repos/making/blog.ik.am/downloads\",\"issues_url\":\"https://api.github.com/repos/making/blog.ik.am/issues{/number}\",\"pulls_url\":\"https://api.github.com/repos/making/blog.ik.am/pulls{/number}\",\"milestones_url\":\"https://api.github.com/repos/making/blog.ik.am/milestones{/number}\",\"notifications_url\":\"https://api.github.com/repos/making/blog.ik.am/notifications{?since,all,participating}\",\"labels_url\":\"https://api.github.com/repos/making/blog.ik.am/labels{/name}\",\"releases_url\":\"https://api.github.com/repos/making/blog.ik.am/releases{/id}\",\"deployments_url\":\"https://api.github.com/repos/making/blog.ik.am/deployments\",\"created_at\":\"2015-12-20T17:55:09Z\",\"updated_at\":\"2023-01-30T07:33:26Z\",\"pushed_at\":\"2023-02-17T08:10:45Z\",\"git_url\":\"git://github.com/making/blog.ik.am.git\",\"ssh_url\":\"git@github.com:making/blog.ik.am.git\",\"clone_url\":\"https://github.com/making/blog.ik.am.git\",\"svn_url\":\"https://github.com/making/blog.ik.am\",\"homepage\":\"https://ik.am\",\"size\":3638,\"stargazers_count\":4,\"watchers_count\":4,\"language\":null,\"has_issues\":true,\"has_projects\":true,\"has_downloads\":true,\"has_wiki\":true,\"has_pages\":false,\"has_discussions\":false,\"forks_count\":7,\"mirror_url\":null,\"archived\":false,\"disabled\":false,\"open_issues_count\":9,\"license\":null,\"allow_forking\":true,\"is_template\":false,\"web_commit_signoff_required\":false,\"topics\":[],\"visibility\":\"public\",\"forks\":7,\"open_issues\":9,\"watchers\":4,\"default_branch\":\"master\"},\"sender\":{\"login\":\"making\",\"id\":106908,\"node_id\":\"MDQ6VXNlcjEwNjkwOA==\",\"avatar_url\":\"https://avatars.githubusercontent.com/u/106908?v=4\",\"gravatar_id\":\"\",\"url\":\"https://api.github.com/users/making\",\"html_url\":\"https://github.com/making\",\"followers_url\":\"https://api.github.com/users/making/followers\",\"following_url\":\"https://api.github.com/users/making/following{/other_user}\",\"gists_url\":\"https://api.github.com/users/making/gists{/gist_id}\",\"starred_url\":\"https://api.github.com/users/making/starred{/owner}{/repo}\",\"subscriptions_url\":\"https://api.github.com/users/making/subscriptions\",\"organizations_url\":\"https://api.github.com/users/making/orgs\",\"repos_url\":\"https://api.github.com/users/making/repos\",\"events_url\":\"https://api.github.com/users/making/events{/privacy}\",\"received_events_url\":\"https://api.github.com/users/making/received_events\",\"type\":\"User\",\"site_admin\":false}}";
		final WebhookVerifier verifierSha1 = WebhookVerifier.gitHubSha1("mysecret");
		assertThat(verifierSha1.sign(payload)).isEqualTo("sha1=86113fc14033057267fce7de17d32d9bd49fba88");
		final WebhookVerifier verifierSha256 = WebhookVerifier.gitHubSha256("mysecret");
		assertThat(verifierSha256.sign(payload))
			.isEqualTo("sha256=ad4327fdb7670348eed766ee96c4164809cb49e761581fd4678629b31bbee362");
	}

}