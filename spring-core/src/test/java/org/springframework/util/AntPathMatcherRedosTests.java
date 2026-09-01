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

package org.springframework.util;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Regression tests for CVE-2026-41848: an Ant-style pattern reaching
 * {@link AntPathMatcher} is compiled to a regular expression, and a pattern with
 * repeated wildcard groups backtracks catastrophically against a string that
 * cannot match.
 *
 * <p>Measured on the released spring-core 5.1.20.RELEASE jar under JDK 8, the
 * pattern below does not complete within four seconds.
 *
 * <p>JUnit 4 and plain {@code org.junit.Assert}, which is this baseline's own test
 * convention -- spring-core's tests here are JUnit 4 and AssertJ is not on their
 * classpath. The match runs on a separate thread so the vulnerable behaviour shows
 * up as a timeout rather than hanging the suite.
 */
public class AntPathMatcherRedosTests {

	private static final int TIMEOUT_SECONDS = 10;

	private final AntPathMatcher pathMatcher = new AntPathMatcher();


	@Test
	public void matchAbortsInsteadOfBacktrackingCatastrophically() throws Exception {
		String pattern = "/x/" + repeat("*a", 12) + "*b";
		String path = "/x/" + repeat("a", 40);

		Throwable thrown = matchWithin(pattern, path);

		assertNotNull("the guard did not abort the match", thrown);
		assertTrue("expected IllegalStateException but got " + thrown,
				thrown instanceof IllegalStateException);
		assertTrue("unexpected message: " + thrown.getMessage(), thrown.getMessage() != null
				&& thrown.getMessage().contains("Too many character access attempts"));
	}

	@Test
	public void ordinaryPatternsAreUnaffected() {
		assertTrue(this.pathMatcher.match("/static/**", "/static/css/app.css"));
		assertTrue(this.pathMatcher.match("/static/*.css", "/static/app.css"));
		assertFalse(this.pathMatcher.match("/static/*.css", "/static/app.js"));
		assertTrue(this.pathMatcher.match("/x/{name}.css", "/x/app.css"));
	}


	/**
	 * Run the match on a daemon thread and return whatever it threw, failing the
	 * test on a timeout if it has not finished within {@link #TIMEOUT_SECONDS}.
	 */
	private Throwable matchWithin(final String pattern, final String path) throws Exception {
		ExecutorService executor = Executors.newSingleThreadExecutor(new ThreadFactory() {
			@Override
			public Thread newThread(Runnable runnable) {
				Thread thread = new Thread(runnable, "ant-path-matcher-redos");
				thread.setDaemon(true);
				return thread;
			}
		});
		try {
			Future<Throwable> outcome = executor.submit(new Callable<Throwable>() {
				@Override
				public Throwable call() {
					try {
						AntPathMatcherRedosTests.this.pathMatcher.match(pattern, path);
						return null;
					}
					catch (Throwable ex) {
						return ex;
					}
				}
			});
			return outcome.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
		}
		finally {
			executor.shutdownNow();
		}
	}

	private static String repeat(String text, int count) {
		StringBuilder sb = new StringBuilder(text.length() * count);
		for (int i = 0; i < count; i++) {
			sb.append(text);
		}
		return sb.toString();
	}

}
