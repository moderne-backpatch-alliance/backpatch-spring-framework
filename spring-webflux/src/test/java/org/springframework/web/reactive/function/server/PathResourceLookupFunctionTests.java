/*
 * Copyright 2002-2020 the original author or authors.
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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.web.testfixture.http.server.reactive.MockServerHttpRequest;
import org.springframework.web.testfixture.server.MockServerWebExchange;

/**
 * @author Arjen Poutsma
 */
public class PathResourceLookupFunctionTests {

	@Test
	public void normal() throws Exception {
		ClassPathResource location = new ClassPathResource("org/springframework/web/reactive/function/server/");

		PathResourceLookupFunction
				function = new PathResourceLookupFunction("/resources/**", location);
		MockServerHttpRequest mockRequest = MockServerHttpRequest.get("https://localhost/resources/response.txt").build();
		ServerRequest request = new DefaultServerRequest(MockServerWebExchange.from(mockRequest), Collections.emptyList());
		Mono<Resource> result = function.apply(request);

		File expected = new ClassPathResource("response.txt", getClass()).getFile();
		StepVerifier.create(result)
				.expectNextMatches(resource -> {
					try {
						return expected.equals(resource.getFile());
					}
					catch (IOException ex) {
						return false;
					}
				})
				.expectComplete()
				.verify();
	}

	@Test
	public void subPath() throws Exception {
		ClassPathResource location = new ClassPathResource("org/springframework/web/reactive/function/server/");

		PathResourceLookupFunction function = new PathResourceLookupFunction("/resources/**", location);
		MockServerHttpRequest mockRequest = MockServerHttpRequest.get("https://localhost/resources/child/response.txt").build();
		ServerRequest request = new DefaultServerRequest(MockServerWebExchange.from(mockRequest), Collections.emptyList());
		Mono<Resource> result = function.apply(request);
		String path = "org/springframework/web/reactive/function/server/child/response.txt";
		File expected = new ClassPathResource(path).getFile();
		StepVerifier.create(result)
				.expectNextMatches(resource -> {
					try {
						return expected.equals(resource.getFile());
					}
					catch (IOException ex) {
						return false;
					}
				})
				.expectComplete()
				.verify();
	}

	@Test
	public void notFound() throws Exception {
		ClassPathResource location = new ClassPathResource("org/springframework/web/reactive/function/server/");

		PathResourceLookupFunction function = new PathResourceLookupFunction("/resources/**", location);
		MockServerHttpRequest mockRequest = MockServerHttpRequest.get("https://example.com").build();
		ServerRequest request = new DefaultServerRequest(MockServerWebExchange.from(mockRequest), Collections.emptyList());
		Mono<Resource> result = function.apply(request);
		StepVerifier.create(result)
				.expectComplete()
				.verify();
	}

	// The payloads MEASURED to read a file outside the location at this baseline.
	// The list is the servlet one: three of these escape through the reactive
	// lookup and the rest do not, and asserting all nine keeps the two artifacts
	// on the same evidence rather than on whichever subset happened to bite.
	// The location is built WITHOUT a trailing slash -- with one, every payload
	// is already refused at 6.0.23 and the test would prove nothing.
	private static final List<String> TRAVERSAL_PAYLOADS = List.of(
			"/resources/public/../secret.txt",
			"/resources/public/..%2fsecret.txt",
			"/resources/public/..//secret.txt",
			"/resources/public/.././secret.txt",
			"/resources/public/%2e%2e/secret.txt",
			"/resources/public/%2e%2e%2fsecret.txt",
			"/resources/public/%2E%2E/secret.txt",
			"/resources/public/.%2e/secret.txt",
			"/resources/public/%2e./secret.txt");

	@Test  // CVE-2024-38816, CVE-2024-38819
	public void doesNotServeResourceOutsideFileSystemLocation(@TempDir Path root) throws Exception {
		PathResourceLookupFunction function = new PathResourceLookupFunction(
				"/resources/**", new FileSystemResource(layout(root).toString()));

		for (String payload : TRAVERSAL_PAYLOADS) {
			MockServerHttpRequest mockRequest = MockServerHttpRequest.get("https://localhost" + payload).build();
			ServerRequest request = new DefaultServerRequest(
					MockServerWebExchange.from(mockRequest), Collections.emptyList());
			StepVerifier.create(function.apply(request))
					.as("payload " + payload + " must not resolve a resource")
					.expectComplete()
					.verify();
		}
	}

	@Test  // CVE-2024-38816, CVE-2024-38819 -- the negative control
	public void servesResourceInsideFileSystemLocation(@TempDir Path root) throws Exception {
		Path served = layout(root);
		PathResourceLookupFunction function = new PathResourceLookupFunction(
				"/resources/**", new FileSystemResource(served + "/"));
		MockServerHttpRequest mockRequest = MockServerHttpRequest.get("https://localhost/resources/index.txt").build();
		ServerRequest request = new DefaultServerRequest(
				MockServerWebExchange.from(mockRequest), Collections.emptyList());

		File expected = served.resolve("index.txt").toFile();
		StepVerifier.create(function.apply(request))
				.expectNextMatches(resource -> {
					try {
						return expected.equals(resource.getFile());
					}
					catch (IOException ex) {
						return false;
					}
				})
				.expectComplete()
				.verify();
	}

	/** A served directory holding one legitimate file, beside a secret the payloads reach for. */
	private static Path layout(Path root) throws Exception {
		Files.write(root.resolve("secret.txt"), "secret".getBytes(StandardCharsets.UTF_8));
		Path served = Files.createDirectory(root.resolve("public"));
		Files.write(served.resolve("index.txt"), "public".getBytes(StandardCharsets.UTF_8));
		return served;
	}

	@Test
	public void composeResourceLookupFunction() throws Exception {
		ClassPathResource defaultResource = new ClassPathResource("response.txt", getClass());

		Function<ServerRequest, Mono<Resource>> lookupFunction =
				new PathResourceLookupFunction("/resources/**",
						new ClassPathResource("org/springframework/web/reactive/function/server/"));

		Function<ServerRequest, Mono<Resource>> customLookupFunction =
				lookupFunction.andThen(resourceMono -> resourceMono
								.switchIfEmpty(Mono.just(defaultResource)));

		MockServerHttpRequest mockRequest = MockServerHttpRequest.get("https://localhost/resources/foo").build();
		ServerRequest request = new DefaultServerRequest(MockServerWebExchange.from(mockRequest), Collections.emptyList());

		Mono<Resource> result = customLookupFunction.apply(request);
		StepVerifier.create(result)
				.expectNextMatches(resource -> {
					try {
						return defaultResource.getFile().equals(resource.getFile());
					}
					catch (IOException ex) {
						return false;
					}
				})
				.expectComplete()
				.verify();
	}

}
