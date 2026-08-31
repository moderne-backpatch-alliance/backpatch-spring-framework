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
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * CVE-2024-22259: host-validation bypass in {@link UriComponentsBuilder}, reported as
 * "the same as CVE-2024-22243, but with different input".
 *
 * <p>Two shapes are covered here, both of which end with {@code getHost()} reporting
 * something other than the authority the URL actually carries:
 *
 * <ul>
 * <li>A {@code '['} inside the authority still truncated the host, because the host
 * expression excluded it. {@code https://example.com[evil.com/} reported the host as
 * {@code example.com} and pushed {@code [evil.com} into the path, so an allow-list on
 * {@code example.com} passed a URL whose authority is not {@code example.com}.</li>
 * <li>The user-info expression stopped at the first {@code '@'}, so with more than one
 * of them the host group started too early and swallowed the rest.</li>
 * </ul>
 *
 * <p>Letting user-info span {@code '@'} and the host span {@code '['} fixes both, and
 * it is what makes the paired IPv6 well-formedness check necessary: once {@code '['}
 * can reach the host group, a host that opens a bracket must also close it.
 *
 * <p>Expected values were captured by running the same inputs through the released
 * spring-web 5.3.34 jar, not derived by reading the expressions.
 *
 * @see <a href="https://spring.io/security/cve-2024-22259">CVE-2024-22259</a>
 */
public class UriComponentsBuilderUserInfoHostBypassTests {

	@Test
	public void fromUriStringWhenBracketInAuthorityThenHostIsNotTruncated() {
		assertThat(UriComponentsBuilder.fromUriString("https://example.com[evil.com/").build().getHost())
				.isEqualTo("example.com[evil.com");
	}

	@Test
	public void fromHttpUrlWhenBracketInAuthorityThenHostIsNotTruncated() {
		assertThat(UriComponentsBuilder.fromHttpUrl("https://example.com[evil.com/").build().getHost())
				.isEqualTo("example.com[evil.com");
	}

	@Test
	public void fromUriStringWhenTwoAtSignsThenHostIsAfterTheLastAt() {
		assertThat(UriComponentsBuilder.fromUriString("https://example.com@evil.com@evil.com/").build().getHost())
				.isEqualTo("evil.com");
	}

	@Test
	public void fromHttpUrlWhenTwoAtSignsThenHostIsAfterTheLastAt() {
		assertThat(UriComponentsBuilder.fromHttpUrl("https://example.com@evil.com@evil.com/").build().getHost())
				.isEqualTo("evil.com");
	}

	@Test
	public void fromUriStringWhenUnclosedIpv6BracketThenRejected() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> UriComponentsBuilder.fromUriString("https://[evil.com/").build())
				.withMessageContaining("Invalid IPV6 host");
	}

	@Test
	public void fromHttpUrlWhenUnclosedIpv6BracketThenRejected() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> UriComponentsBuilder.fromHttpUrl("https://[evil.com/").build())
				.withMessageContaining("Invalid IPV6 host");
	}

	@Test
	public void fromOriginHeaderWhenUnclosedIpv6BracketThenRejected() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> UriComponentsBuilder.fromOriginHeader("https://[evil.com"))
				.withMessageContaining("Invalid IPV6 host");
	}


	// No-regression guards. A well-formed IPv6 authority still parses, on both sides of
	// the patch, through every entry point the check was added to.

	@Test
	public void fromUriStringWhenWellFormedIpv6ThenAccepted() {
		assertThat(UriComponentsBuilder.fromUriString("https://[::1]:8080/path").build().getHost()).isEqualTo("[::1]");
	}

	@Test
	public void fromHttpUrlWhenWellFormedIpv6ThenAccepted() {
		assertThat(UriComponentsBuilder.fromHttpUrl("https://[::1]:8080/path").build().getHost()).isEqualTo("[::1]");
	}

	@Test
	public void fromOriginHeaderWhenWellFormedThenAccepted() {
		UriComponents components = UriComponentsBuilder.fromOriginHeader("https://example.com:8080").build();
		assertThat(components.getHost()).isEqualTo("example.com");
		assertThat(components.getPort()).isEqualTo(8080);
	}

	@Test
	public void fromOriginHeaderWhenWellFormedIpv6ThenAccepted() {
		assertThat(UriComponentsBuilder.fromOriginHeader("https://[::1]:8080").build().getHost()).isEqualTo("[::1]");
	}

}
