/*
 * Copyright 2002-2023 the original author or authors.
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

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.handler.PathPatternsTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

/**
 * @author Arjen Poutsma
 */
class PathResourceLookupFunctionTests {

	@Test
	void normal() throws Exception {
		ClassPathResource location = new ClassPathResource("org/springframework/web/servlet/function/");
		PathResourceLookupFunction function = new PathResourceLookupFunction("/resources/**", location);
		ServerRequest request = initRequest("GET", "/resources/response.txt");

		Optional<Resource> result = function.apply(request);
		assertThat(result).isPresent();

		File expected = new ClassPathResource("response.txt", getClass()).getFile();
		assertThat(result.get().getFile()).isEqualTo(expected);
	}

	@Test
	void subPath() throws Exception {
		ClassPathResource location = new ClassPathResource("org/springframework/web/servlet/function/");
		PathResourceLookupFunction function = new PathResourceLookupFunction("/resources/**", location);
		ServerRequest request = initRequest("GET", "/resources/child/response.txt");

		Optional<Resource> result = function.apply(request);
		assertThat(result).isPresent();

		File expected = new ClassPathResource("org/springframework/web/servlet/function/child/response.txt").getFile();
		assertThat(result.get().getFile()).isEqualTo(expected);
	}

	@Test
	void notFound() {
		ClassPathResource location = new ClassPathResource("org/springframework/web/reactive/function/server/");
		PathResourceLookupFunction function = new PathResourceLookupFunction("/resources/**", location);
		ServerRequest request = initRequest("GET", "/resources/foo.txt");

		Optional<Resource> result = function.apply(request);
		assertThat(result).isNotPresent();
	}

	@Test
	void composeResourceLookupFunction() throws Exception {
		ClassPathResource defaultResource = new ClassPathResource("response.txt", getClass());

		Function<ServerRequest, Optional<Resource>> lookupFunction =
				new PathResourceLookupFunction("/resources/**",
						new ClassPathResource("org/springframework/web/servlet/function/"));

		Function<ServerRequest, Optional<Resource>> customLookupFunction =
				lookupFunction.andThen((Optional<Resource> optionalResource) -> {
					if (optionalResource.isPresent()) {
						return optionalResource;
					}
					else {
						return Optional.of(defaultResource);
					}
				});

		ServerRequest request = initRequest("GET", "/resources/foo");

		Optional<Resource> result = customLookupFunction.apply(request);
		assertThat(result).isPresent();

		assertThat(result.get().getFile()).isEqualTo(defaultResource.getFile());
	}

	// The nine payloads MEASURED to read a file outside the location at this
	// baseline. The location is built WITHOUT a trailing slash -- the ordinary
	// spelling -- because that is what the escape needs: with a trailing slash
	// every one of these is already refused at 6.0.23, so a test written that
	// way would pass with or without the fix.
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
	void doesNotServeResourceOutsideFileSystemLocation(@TempDir Path root) throws Exception {
		PathResourceLookupFunction function = new PathResourceLookupFunction(
				"/resources/**", new FileSystemResource(layout(root).toString()));

		// assertAll so one payload resolving does not hide the rest
		assertAll(TRAVERSAL_PAYLOADS.stream().map(payload -> () ->
				assertThat(function.apply(initRequest("GET", payload)))
						.as("payload %s must not resolve a resource", payload)
						.isNotPresent()));
	}

	@Test  // CVE-2024-38816, CVE-2024-38819 -- the negative control
	void servesResourceInsideFileSystemLocation(@TempDir Path root) throws Exception {
		Path served = layout(root);
		PathResourceLookupFunction function = new PathResourceLookupFunction(
				"/resources/**", new FileSystemResource(served + "/"));

		Optional<Resource> result = function.apply(initRequest("GET", "/resources/index.txt"));
		assertThat(result).isPresent();
		assertThat(result.get().getFile()).isEqualTo(served.resolve("index.txt").toFile());
	}

	/** A served directory holding one legitimate file, beside a secret the payloads reach for. */
	private static Path layout(Path root) throws Exception {
		Files.write(root.resolve("secret.txt"), "secret".getBytes(StandardCharsets.UTF_8));
		Path served = Files.createDirectory(root.resolve("public"));
		Files.write(served.resolve("index.txt"), "public".getBytes(StandardCharsets.UTF_8));
		return served;
	}

	private ServerRequest initRequest(String httpMethod, String requestUri) {
		return new DefaultServerRequest(
				PathPatternsTestUtils.initRequest(httpMethod, requestUri, true),
				Collections.emptyList());
	}

}
