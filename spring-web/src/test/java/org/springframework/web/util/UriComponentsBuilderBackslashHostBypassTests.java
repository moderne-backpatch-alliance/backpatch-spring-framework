/*
 * Copyright 2002-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.web.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CVE-2024-22262: host-validation bypass in {@link UriComponentsBuilder} when the
 * authority carries a backslash.
 *
 * <p>A backslash is not a host character. Browsers and WHATWG-conformant clients
 * treat it as a {@code '/'} in a URL with a special scheme, so the authority ends
 * there. The scheme, user-info and host expressions all admitted it, so the builder
 * carried it into the host instead: {@code https://evil.com\.example.com/} reported
 * the host as {@code evil.com\.example.com}. An application checking
 * {@code host.endsWith(".example.com")} - the ordinary way to allow a company's own
 * subdomains - passes it, and the request then goes to {@code evil.com}. Open
 * redirect (CWE-601) or SSRF, CVSS 8.1.
 *
 * <p>Excluding the backslash makes the host stop where a client stops reading it.
 *
 * <p>Expected values were captured by running the same inputs through the released
 * spring-web 5.3.34 jar, not derived by reading the expressions.
 *
 * @see <a href="https://spring.io/security/cve-2024-22262">CVE-2024-22262</a>
 */
public class UriComponentsBuilderBackslashHostBypassTests {

	@Test
	public void fromUriStringWhenBackslashInHostThenHostStopsAtTheBackslash() {
		assertThat(UriComponentsBuilder.fromUriString("https://evil.com\\.example.com/").build().getHost())
				.isEqualTo("evil.com");
	}

	@Test
	public void fromHttpUrlWhenBackslashInHostThenHostStopsAtTheBackslash() {
		assertThat(UriComponentsBuilder.fromHttpUrl("https://evil.com\\.example.com/").build().getHost())
				.isEqualTo("evil.com");
	}

	@Test
	public void fromUriStringWhenBackslashPrefixesUserInfoThenHostStopsAtTheBackslash() {
		assertThat(UriComponentsBuilder.fromUriString("https://example.com\\@evil.com/").build().getHost())
				.isEqualTo("example.com");
	}

	@Test
	public void fromHttpUrlWhenBackslashPrefixesUserInfoThenHostStopsAtTheBackslash() {
		assertThat(UriComponentsBuilder.fromHttpUrl("https://example.com\\@evil.com/").build().getHost())
				.isEqualTo("example.com");
	}

	@Test
	public void fromUriStringWhenBackslashJoinsTwoNamesThenHostStopsAtTheBackslash() {
		assertThat(UriComponentsBuilder.fromUriString("https://example.com\\evil.com/").build().getHost())
				.isEqualTo("example.com");
	}

	@Test
	public void fromUriStringWhenBackslashAfterPortThenHostAndPortUnaffected() {
		UriComponents components = UriComponentsBuilder.fromUriString("https://example.com:80\\@evil.com/").build();
		assertThat(components.getHost()).isEqualTo("example.com");
		assertThat(components.getPort()).isEqualTo(80);
	}


	// No-regression guards. The backslash is excluded from the scheme, user-info and
	// host only - it is still an ordinary character everywhere after the authority.

	@Test
	public void fromUriStringWhenBackslashInPathThenRetained() {
		assertThat(UriComponentsBuilder.fromUriString("https://example.com/p\\q").build().getPath()).isEqualTo("/p\\q");
	}

	@Test
	public void fromUriStringWhenBackslashInQueryThenRetained() {
		assertThat(UriComponentsBuilder.fromUriString("https://example.com?q=a\\b").build().getQuery())
				.isEqualTo("q=a\\b");
	}

	@Test
	public void fromUriStringWhenPlainUrlThenUnchanged() {
		UriComponents components = UriComponentsBuilder.fromUriString("https://example.com:8080/path?q=1#f").build();
		assertThat(components.getScheme()).isEqualTo("https");
		assertThat(components.getHost()).isEqualTo("example.com");
		assertThat(components.getPort()).isEqualTo(8080);
	}

}
