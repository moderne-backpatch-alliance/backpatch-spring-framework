/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.web.context.request;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.test.MockHttpServletRequest;
import org.springframework.mock.web.test.MockHttpServletResponse;

import static org.junit.Assert.*;

/**
 * Parsing of ETag lists in conditional request headers (CVE-2024-38809).
 */
public class ConditionalRequestETagParsingTests {

	private static final long TIME_BOUND_MILLIS = 1000;


	private static String longIfNoneMatchValue() {
		StringBuilder sb = new StringBuilder("\"a\",x");
		for (int i = 0; i < 30000; i++) {
			sb.append(' ');
		}
		return sb.append('x').toString();
	}

	private static void assertWithinTimeBound(long startNanos) {
		long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
		assertTrue("Took " + elapsed + " ms, bound is " + TIME_BOUND_MILLIS + " ms", elapsed < TIME_BOUND_MILLIS);
	}


	@Test
	public void httpHeadersParsesLongIfNoneMatchWithinTimeBound() {
		HttpHeaders headers = new HttpHeaders();
		headers.setIfNoneMatch(longIfNoneMatchValue());
		long start = System.nanoTime();
		List<String> result = headers.getIfNoneMatch();
		assertWithinTimeBound(start);
		assertEquals(Arrays.asList("\"a\""), result);
	}

	@Test
	public void servletWebRequestParsesLongIfNoneMatchWithinTimeBound() {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		request.addHeader(HttpHeaders.IF_NONE_MATCH, longIfNoneMatchValue());
		ServletWebRequest webRequest = new ServletWebRequest(request, new MockHttpServletResponse());
		long start = System.nanoTime();
		boolean notModified = webRequest.checkNotModified("\"b\"");
		assertWithinTimeBound(start);
		assertFalse(notModified);
	}

	@Test
	public void httpHeadersParsesWeakAndStrongETags() {
		HttpHeaders headers = new HttpHeaders();
		headers.setIfNoneMatch(Arrays.asList("W/\"v1\", \"v2\"", "*"));
		assertEquals(Arrays.asList("W/\"v1\"", "\"v2\"", "*"), headers.getIfNoneMatch());
	}

	@Test
	public void servletWebRequestMatchesWeakAndStrongETags() {
		assertTrue(checkNotModified("W/\"v1\", \"v2\"", "\"v1\""));
		assertTrue(checkNotModified("W/\"v1\", \"v2\"", "W/\"v2\""));
		assertTrue(checkNotModified("\"v2\"", "v2"));
		assertFalse(checkNotModified("W/\"v1\", \"v2\"", "\"v3\""));
	}

	private static boolean checkNotModified(String ifNoneMatch, String etag) {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		request.addHeader(HttpHeaders.IF_NONE_MATCH, ifNoneMatch);
		return new ServletWebRequest(request, new MockHttpServletResponse()).checkNotModified(etag);
	}

}
