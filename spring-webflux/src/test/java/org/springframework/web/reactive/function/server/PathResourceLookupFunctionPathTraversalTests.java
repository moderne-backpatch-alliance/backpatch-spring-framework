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

package org.springframework.web.reactive.function.server;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.web.testfixture.http.server.reactive.MockServerHttpRequest;
import org.springframework.web.testfixture.server.MockServerWebExchange;

/**
 * Regression tests for CVE-2024-38816: path traversal in WebFlux.fn
 * {@link RouterFunctions#resources(String, Resource) RouterFunctions.resources}
 * when the location is a {@link FileSystemResource}.
 *
 * <p>Backpatch-fresh: not present upstream in 5.3.x. Exercises
 * {@link PathResourceLookupFunction} directly with traversal payloads and a
 * location pointing at a {@link Files#createTempDirectory temp directory}, so
 * an outside-of-location file actually exists on disk for the test to attempt
 * to escape to.
 *
 * @see PathResourceLookupFunction
 */
public class PathResourceLookupFunctionPathTraversalTests {

	private Path locationDir;

	private Path siblingSecret;

	private PathResourceLookupFunction function;

	@BeforeEach
	void setUp() throws IOException {
		Path tempRoot = Files.createTempDirectory("bp-cve-2024-38816-webflux-");
		this.locationDir = Files.createDirectory(tempRoot.resolve("location"));
		Files.write(this.locationDir.resolve("legit.txt"),
				"legit content".getBytes(StandardCharsets.UTF_8));
		this.siblingSecret = Files.write(tempRoot.resolve("sibling-secret.txt"),
				"SECRET".getBytes(StandardCharsets.UTF_8));

		FileSystemResource location = new FileSystemResource(this.locationDir.toString() + "/");
		this.function = new PathResourceLookupFunction("/resources/**", location);
	}

	@AfterEach
	void tearDown() throws IOException {
		Files.deleteIfExists(this.siblingSecret);
		Files.deleteIfExists(this.locationDir.resolve("legit.txt"));
		Files.deleteIfExists(this.locationDir);
		Files.deleteIfExists(this.locationDir.getParent());
	}

	@Test
	public void rejectsParentDirectoryEscape() {
		// Baseline: legit file under location resolves successfully — guards
		// against an over-block in the patched code.
		StepVerifier.create(lookup("/resources/legit.txt"))
				.expectNextCount(1)
				.expectComplete()
				.verify();

		// Unencoded traversal payloads.
		assertRejected("/resources/../sibling-secret.txt");
		assertRejected("/resources/..\\sibling-secret.txt");

		// Encoded payloads — included here so the WebFlux side has parity
		// with the WebMvc test's encoded-sequence coverage even though the
		// manifest only lists one reactive method.
		assertRejected("/resources/%2e%2e%2fsibling-secret.txt");
		assertRejected("/resources/%2e%2e/sibling-secret.txt");
		assertRejected("/resources/..%2fsibling-secret.txt");
		assertRejected("/resources/%252e%252e%252fsibling-secret.txt");
	}

	private void assertRejected(String requestPath) {
		// StepVerifier.as(String) only takes a label; on failure the label is
		// what surfaces, so include the offending payload inline.
		StepVerifier.create(lookup(requestPath))
				.as("traversal payload must not resolve a resource: " + requestPath)
				.expectComplete()
				.verify();
	}

	private Mono<Resource> lookup(String requestPath) {
		MockServerHttpRequest mockRequest =
				MockServerHttpRequest.get("https://localhost" + requestPath).build();
		ServerRequest request = new DefaultServerRequest(
				MockServerWebExchange.from(mockRequest), Collections.emptyList());
		return this.function.apply(request);
	}

}
