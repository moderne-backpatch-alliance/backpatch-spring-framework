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

import org.junit.Test;

import static org.junit.Assert.*;

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
		assertEquals("evil.com",
				UriComponentsBuilder.fromUriString("https://example.com[@evil.com/").build().getHost());
	}

	@Test
	public void fromHttpUrlWhenBracketPrecedesUserInfoThenHostIsTheRealAuthority() {
		assertEquals("evil.com",
				UriComponentsBuilder.fromHttpUrl("https://example.com[@evil.com/").build().getHost());
	}

	@Test
	public void fromUriStringWhenBracketAndPortPrecedeUserInfoThenHostIsTheRealAuthority() {
		assertEquals("evil.com",
				UriComponentsBuilder.fromUriString("https://example.com[:80@evil.com/").build().getHost());
	}

	@Test
	public void fromHttpUrlWhenBracketAndPortPrecedeUserInfoThenHostIsTheRealAuthority() {
		assertEquals("evil.com",
				UriComponentsBuilder.fromHttpUrl("https://example.com[:80@evil.com/").build().getHost());
	}


	// No-regression guards. These pass on the unpatched baseline too: relaxing the
	// user-info, host and scheme expressions must not change how an ordinary URL parses.

	@Test
	public void fromUriStringWhenPlainUrlThenUnchanged() {
		UriComponents components = UriComponentsBuilder.fromUriString("https://example.com:8080/path?q=1#f").build();
		assertEquals("https", components.getScheme());
		assertEquals("example.com", components.getHost());
		assertEquals(8080, components.getPort());
		assertEquals("/path", components.getPath());
		assertEquals("q=1", components.getQuery());
		assertEquals("f", components.getFragment());
	}

	@Test
	public void fromUriStringWhenUserInfoThenUnchanged() {
		UriComponents components = UriComponentsBuilder.fromUriString("https://user:pw@example.com/path").build();
		assertEquals("user:pw", components.getUserInfo());
		assertEquals("example.com", components.getHost());
	}

	@Test
	public void fromUriStringWhenIpv6HostThenUnchanged() {
		UriComponents components = UriComponentsBuilder.fromUriString("https://[::1]:8080/path").build();
		assertEquals("[::1]", components.getHost());
		assertEquals(8080, components.getPort());
	}

	@Test
	public void fromUriStringWhenIpv6ZoneIdHostThenUnchanged() {
		assertEquals("[fe80::1%25eth0]",
				UriComponentsBuilder.fromUriString("https://[fe80::1%25eth0]:80/path").build().getHost());
	}

	@Test
	public void fromUriStringWhenOpaqueUriThenNoHost() {
		assertNull(UriComponentsBuilder.fromUriString("mailto:user@example.com").build().getHost());
	}

	@Test
	public void fromUriStringWhenPortIsUriVariableThenUnchanged() {
		assertEquals(8080,
				UriComponentsBuilder.fromUriString("https://example.com:{port}/path").buildAndExpand(8080).getPort());
	}

}
