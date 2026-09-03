/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.web.servlet.function;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.handler.PathPatternsTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

/**
 * Regression tests for CVE-2024-38816: path traversal in WebMvc.fn
 * {@link RouterFunctions#resources(String, Resource) RouterFunctions.resources}
 * when the location is a {@link FileSystemResource}.
 *
 * <p>Backpatch-fresh: not present upstream in 5.3.x. Exercises
 * {@link PathResourceLookupFunction} directly with the same shape of test
 * scaffolding as the existing {@code PathResourceLookupFunctionTests}, but
 * with traversal-payload inputs and a location pointing at a
 * {@link Files#createTempDirectory temp directory} so an outside-of-location
 * file actually exists on disk for the test to attempt to escape to.
 *
 * @see PathResourceLookupFunction
 */
class PathResourceLookupFunctionPathTraversalTests {

	private Path locationDir;

	private Path siblingSecret;

	private PathResourceLookupFunction function;

	@BeforeEach
	void setUp() throws IOException {
		Path tempRoot = Files.createTempDirectory("bp-cve-2024-38816-webmvc-");
		this.locationDir = Files.createDirectory(tempRoot.resolve("location"));
		Files.write(this.locationDir.resolve("legit.txt"),
				"legit content".getBytes(StandardCharsets.UTF_8));
		// sibling-of-location file the traversal payloads attempt to reach
		this.siblingSecret = Files.write(tempRoot.resolve("sibling-secret.txt"),
				"SECRET".getBytes(StandardCharsets.UTF_8));

		// Location resource must end with "/" so FileSystemResource.createRelative
		// resolves children correctly relative to the directory.
		FileSystemResource location = new FileSystemResource(this.locationDir.toString() + "/");
		this.function = new PathResourceLookupFunction("/resources/**", location);
	}

	@AfterEach
	void tearDown() throws IOException {
		// best-effort cleanup; tests are short-lived and tempdir leaks are
		// tolerable, but we tidy up to avoid noise under repeat runs.
		Files.deleteIfExists(this.siblingSecret);
		Files.deleteIfExists(this.locationDir.resolve("legit.txt"));
		Files.deleteIfExists(this.locationDir);
		Files.deleteIfExists(this.locationDir.getParent());
	}

	@Test
	void rejectsParentDirectoryEscape() {
		// Legit baseline first: confirms the location wiring works at all,
		// so a later block on a traversal payload is meaningful.
		Optional<Resource> legit = lookup("/resources/legit.txt");
		assertThat(legit).as("baseline legit lookup should succeed").isPresent();

		// Each payload must produce empty — never resolve to siblingSecret.
		assertRejected("/resources/../sibling-secret.txt");
		assertRejected("/resources/..\\sibling-secret.txt");
	}

	@Test
	void rejectsEncodedTraversalSequences() {
		// Single-encoded variants.
		assertRejected("/resources/%2e%2e%2fsibling-secret.txt");
		assertRejected("/resources/%2e%2e/sibling-secret.txt");
		assertRejected("/resources/..%2fsibling-secret.txt");

		// Double-encoded variant — caught either at processPath validation or
		// by isInvalidEncodedInputPath's decode-then-revalidate pass.
		assertRejected("/resources/%252e%252e%252fsibling-secret.txt");
	}

	// The payloads MEASURED to escape at this baseline. They differ from the
	// set above in ONE respect that turns out to decide everything: the
	// location is built WITHOUT a trailing slash. FileSystemResource.
	// createRelative then resolves through StringUtils.applyRelativePath,
	// which drops the last segment and makes the PARENT the effective root.
	// With a trailing slash every payload above is already refused by the
	// UNPATCHED baseline -- measured on Central's spring-webmvc-5.3.39.jar --
	// so rejectsParentDirectoryEscape and rejectsEncodedTraversalSequences
	// pass with or without the fix and cannot witness a regression.
	private static final java.util.List<String> ESCAPING_PAYLOADS = java.util.Arrays.asList(
			"/resources/location/../sibling-secret.txt",
			"/resources/location/..%2fsibling-secret.txt",
			"/resources/location/..//sibling-secret.txt",
			"/resources/location/.././sibling-secret.txt",
			"/resources/location/%2e%2e/sibling-secret.txt",
			"/resources/location/%2e%2e%2fsibling-secret.txt",
			"/resources/location/%2E%2E/sibling-secret.txt",
			"/resources/location/.%2e/sibling-secret.txt",
			"/resources/location/%2e./sibling-secret.txt");

	@Test  // CVE-2024-38819
	void rejectsEscapeFromLocationWithoutTrailingSlash() {
		PathResourceLookupFunction fn = new PathResourceLookupFunction(
				"/resources/**", new FileSystemResource(this.locationDir.toString()));

		// assertAll so one payload resolving does not hide the rest
		assertAll(ESCAPING_PAYLOADS.stream().map(payload -> () ->
				assertThat(fn.apply(request(payload)))
						.as("payload %s must not resolve a resource", payload)
						.isNotPresent()));
	}

	@Test  // CVE-2024-38819 -- the negative control
	void stillServesLegitimateResourceFromLocationWithoutTrailingSlash() {
		PathResourceLookupFunction fn = new PathResourceLookupFunction(
				"/resources/**", new FileSystemResource(this.locationDir.toString()));

		assertThat(fn.apply(request("/resources/location/legit.txt"))).isPresent();
	}

	private ServerRequest request(String requestUri) {
		return new DefaultServerRequest(
				PathPatternsTestUtils.initRequest("GET", requestUri, true),
				Collections.emptyList());
	}

	private void assertRejected(String requestPath) {
		Optional<Resource> result = lookup(requestPath);
		assertThat(result)
				.as("traversal payload %s must not resolve a resource", requestPath)
				.isNotPresent();
	}

	private Optional<Resource> lookup(String requestUri) {
		ServerRequest request = new DefaultServerRequest(
				PathPatternsTestUtils.initRequest("GET", requestUri, true),
				Collections.emptyList());
		return this.function.apply(request);
	}

}
