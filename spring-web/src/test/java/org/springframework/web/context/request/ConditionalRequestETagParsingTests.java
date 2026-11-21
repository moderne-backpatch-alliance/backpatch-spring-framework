/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.web.context.request;

import java.time.Duration;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.web.testfixture.servlet.MockHttpServletRequest;
import org.springframework.web.testfixture.servlet.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeout;

/**
 * Parsing of ETag lists in conditional request headers (CVE-2024-38809).
 */
class ConditionalRequestETagParsingTests {

	private static final Duration TIME_BOUND = Duration.ofSeconds(1);

	private static String longIfNoneMatchValue() {
		StringBuilder sb = new StringBuilder("\"a\",x");
		for (int i = 0; i < 30000; i++) {
			sb.append(' ');
		}
		return sb.append('x').toString();
	}


	@Test
	void httpHeadersParsesLongIfNoneMatchWithinTimeBound() {
		HttpHeaders headers = new HttpHeaders();
		headers.setIfNoneMatch(longIfNoneMatchValue());
		assertTimeout(TIME_BOUND, () -> assertThat(headers.getIfNoneMatch()).containsExactly("\"a\""));
	}

	@Test
	void servletWebRequestParsesLongIfNoneMatchWithinTimeBound() {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		request.addHeader(HttpHeaders.IF_NONE_MATCH, longIfNoneMatchValue());
		ServletWebRequest webRequest = new ServletWebRequest(request, new MockHttpServletResponse());
		assertTimeout(TIME_BOUND, () -> assertThat(webRequest.checkNotModified("\"b\"")).isFalse());
	}

	@Test
	void httpHeadersParsesWeakAndStrongETags() {
		HttpHeaders headers = new HttpHeaders();
		headers.setIfNoneMatch(Arrays.asList("W/\"v1\", \"v2\"", "*"));
		assertThat(headers.getIfNoneMatch()).containsExactly("W/\"v1\"", "\"v2\"", "*");
	}

	@Test
	void servletWebRequestMatchesWeakAndStrongETags() {
		assertThat(checkNotModified("W/\"v1\", \"v2\"", "\"v1\"")).isTrue();
		assertThat(checkNotModified("W/\"v1\", \"v2\"", "W/\"v2\"")).isTrue();
		assertThat(checkNotModified("\"v2\"", "v2")).isTrue();
		assertThat(checkNotModified("W/\"v1\", \"v2\"", "\"v3\"")).isFalse();
	}

	private static boolean checkNotModified(String ifNoneMatch, String etag) {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		request.addHeader(HttpHeaders.IF_NONE_MATCH, ifNoneMatch);
		return new ServletWebRequest(request, new MockHttpServletResponse()).checkNotModified(etag);
	}

}
