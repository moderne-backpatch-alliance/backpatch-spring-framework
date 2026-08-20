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

import static org.junit.Assert.assertEquals;

/**
 * Regression tests for CVE-2026-41845 at the 5.1.20.RELEASE baseline.
 *
 * <p>{@link JavaScriptUtils#javaScriptEscape} escaped the quote characters of the two
 * string-literal forms ECMAScript had in 1999, and neither character of the third.
 * A value escaped for a single- or double-quoted literal and then emitted inside a
 * template literal keeps its backtick and its dollar sign, so the value can close the
 * literal or open a ${...} substitution and execute — cross-site scripting through a
 * helper whose whole purpose is to prevent it.
 *
 * @see <a href="https://spring.io/security/cve-2026-41845">CVE-2026-41845</a>
 */
public class JavaScriptUtilsTemplateLiteralEscapeTests {

	@Test
	public void backtickIsEscaped() {
		assertEquals("\\u0060", JavaScriptUtils.javaScriptEscape("`"));
	}

	@Test
	public void dollarIsEscaped() {
		assertEquals("\\u0024", JavaScriptUtils.javaScriptEscape("$"));
	}

	@Test
	public void substitutionCannotBeOpened() {
		assertEquals("\\u0024{alert(1)}", JavaScriptUtils.javaScriptEscape("${alert(1)}"));
	}

	@Test
	public void templateLiteralCannotBeClosed() {
		assertEquals("\\u0060;alert(1);\\u0060", JavaScriptUtils.javaScriptEscape("`;alert(1);`"));
	}

	@Test
	public void previouslyEscapedCharactersAreUnchanged() {
		assertEquals("\\u003C\\u003E", JavaScriptUtils.javaScriptEscape("<>"));
		assertEquals("\\\"\\'\\\\\\/", JavaScriptUtils.javaScriptEscape("\"'\\/"));
		assertEquals("\\u2028\\u2029", JavaScriptUtils.javaScriptEscape(new StringBuilder().append('\u2028').append('\u2029').toString()));
	}

}
