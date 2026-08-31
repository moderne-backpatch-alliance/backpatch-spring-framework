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
 * CVE-2024-22243: host-validation bypass in {@link UriComponentsBuilder} when the
 * authority carries a {@code '['} ahead of the {@code '@'}.
 *
 * <p>The user-info expression excluded {@code '['}, so on such a URL the user-info
 * group could not match at all. The authority after the {@code '@'} was then parsed
 * as part of the path and {@code getHost()} returned the attacker-chosen prefix. An
 * application that validates the host before using the URL sees {@code example.com},
 * passes its own check, and then issues the request to {@code evil.com} - an open
 * redirect (CWE-601) or SSRF.
 *
 * <p>Expected values were captured by running the same inputs through the released
 * spring-web 5.3.34 jar, not derived by reading the expressions.
 *
 * @see <a href="https://spring.io/security/cve-2024-22243">CVE-2024-22243</a>
 */
public class UriComponentsBuilderBracketHostBypassTests {

	@Test
	public void fromUriStringWhenBracketPrecedesUserInfoThenHostIsTheRealAuthority() {
		assertThat(UriComponentsBuilder.fromUriString("https://example.com[@evil.com/").build().getHost())
				.isEqualTo("evil.com");
	}

	@Test
	public void fromHttpUrlWhenBracketPrecedesUserInfoThenHostIsTheRealAuthority() {
		assertThat(UriComponentsBuilder.fromHttpUrl("https://example.com[@evil.com/").build().getHost())
				.isEqualTo("evil.com");
	}

	@Test
	public void fromUriStringWhenBracketAndPortPrecedeUserInfoThenHostIsTheRealAuthority() {
		assertThat(UriComponentsBuilder.fromUriString("https://example.com[:80@evil.com/").build().getHost())
				.isEqualTo("evil.com");
	}

	@Test
	public void fromHttpUrlWhenBracketAndPortPrecedeUserInfoThenHostIsTheRealAuthority() {
		assertThat(UriComponentsBuilder.fromHttpUrl("https://example.com[:80@evil.com/").build().getHost())
				.isEqualTo("evil.com");
	}


	// No-regression guards. These pass on the unpatched baseline too: relaxing the
	// user-info, host and scheme expressions must not change how an ordinary URL parses.

	@Test
	public void fromUriStringWhenPlainUrlThenUnchanged() {
		UriComponents components = UriComponentsBuilder.fromUriString("https://example.com:8080/path?q=1#f").build();
		assertThat(components.getScheme()).isEqualTo("https");
		assertThat(components.getHost()).isEqualTo("example.com");
		assertThat(components.getPort()).isEqualTo(8080);
		assertThat(components.getPath()).isEqualTo("/path");
		assertThat(components.getQuery()).isEqualTo("q=1");
		assertThat(components.getFragment()).isEqualTo("f");
	}

	@Test
	public void fromUriStringWhenUserInfoThenUnchanged() {
		UriComponents components = UriComponentsBuilder.fromUriString("https://user:pw@example.com/path").build();
		assertThat(components.getUserInfo()).isEqualTo("user:pw");
		assertThat(components.getHost()).isEqualTo("example.com");
	}

	@Test
	public void fromUriStringWhenIpv6HostThenUnchanged() {
		UriComponents components = UriComponentsBuilder.fromUriString("https://[::1]:8080/path").build();
		assertThat(components.getHost()).isEqualTo("[::1]");
		assertThat(components.getPort()).isEqualTo(8080);
	}

	@Test
	public void fromUriStringWhenIpv6ZoneIdHostThenUnchanged() {
		assertThat(UriComponentsBuilder.fromUriString("https://[fe80::1%25eth0]:80/path").build().getHost())
				.isEqualTo("[fe80::1%25eth0]");
	}

	@Test
	public void fromUriStringWhenOpaqueUriThenNoHost() {
		assertThat(UriComponentsBuilder.fromUriString("mailto:user@example.com").build().getHost()).isNull();
	}

	@Test
	public void fromUriStringWhenPortIsUriVariableThenUnchanged() {
		assertThat(UriComponentsBuilder.fromUriString("https://example.com:{port}/path").buildAndExpand(8080).getPort())
				.isEqualTo(8080);
	}

}
