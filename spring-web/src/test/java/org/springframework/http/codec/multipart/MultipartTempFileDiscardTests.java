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

package org.springframework.http.codec.multipart;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import org.springframework.core.ResolvableType;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ReactiveHttpInputMessage;
import org.springframework.http.codec.HttpMessageReader;
import org.springframework.lang.Nullable;
import org.springframework.util.MultiValueMap;
import org.springframework.web.testfixture.http.server.reactive.MockServerHttpRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression tests for CVE-2026-22740.
 *
 * <p>{@link MultipartHttpMessageReader#readMono} collects the parts into a map.
 * When that map is discarded -- the request is abandoned after the parts have
 * been parsed but before the map is delivered -- the temp files backing parts
 * larger than the reader's in-memory limit were left on disk, so a caller could
 * consume disk space without bound.
 *
 * @author Backpatch Alliance
 */
class MultipartTempFileDiscardTests {

	@Test
	void discardedPartMapDeletesTempFiles() throws IOException {
		Path first = createTempFile();
		Path second = createTempFile();
		MultipartHttpMessageReader reader = new MultipartHttpMessageReader(partReaderEmitting(
				Flux.concat(Flux.just(filePart("first", first), filePart("second", second)), Flux.never())));

		Disposable subscription = reader
				.readMono(ResolvableType.forClass(Part.class), request(), Collections.emptyMap())
				.subscribe();

		assertThat(Files.exists(first)).as("parts parsed before cancellation").isTrue();
		subscription.dispose();

		assertThat(Files.exists(first)).as("temp file of discarded part").isFalse();
		assertThat(Files.exists(second)).as("temp file of discarded part").isFalse();
	}

	@Test
	void deliveredPartMapKeepsTempFiles() throws IOException {
		Path file = createTempFile();
		MultipartHttpMessageReader reader = new MultipartHttpMessageReader(
				partReaderEmitting(Flux.just(filePart("first", file))));

		MultiValueMap<String, Part> parts = reader
				.readMono(ResolvableType.forClass(Part.class), request(), Collections.emptyMap())
				.block();

		try {
			assertThat(parts).isNotNull();
			assertThat(parts.getFirst("first")).isNotNull();
			assertThat(Files.exists(file)).as("temp file of a delivered part").isTrue();
		}
		finally {
			Files.deleteIfExists(file);
		}
	}


	private static Path createTempFile() throws IOException {
		Path file = Files.createTempFile("spring-multipart-discard", ".tmp");
		Files.write(file, "content".getBytes(StandardCharsets.UTF_8));
		return file;
	}

	private static Part filePart(String name, Path file) {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentDispositionFormData(name, file.getFileName().toString());
		return DefaultParts.part(headers, file, Schedulers.immediate());
	}

	private static ReactiveHttpInputMessage request() {
		return MockServerHttpRequest.post("/")
				.contentType(MediaType.MULTIPART_FORM_DATA)
				.body(Flux.empty());
	}

	private static HttpMessageReader<Part> partReaderEmitting(Flux<Part> parts) {
		return new HttpMessageReader<Part>() {

			@Override
			public List<MediaType> getReadableMediaTypes() {
				return Collections.singletonList(MediaType.MULTIPART_FORM_DATA);
			}

			@Override
			public boolean canRead(ResolvableType elementType, @Nullable MediaType mediaType) {
				return true;
			}

			@Override
			public Flux<Part> read(ResolvableType elementType, ReactiveHttpInputMessage message,
					Map<String, Object> hints) {
				return parts;
			}

			@Override
			public Mono<Part> readMono(ResolvableType elementType, ReactiveHttpInputMessage message,
					Map<String, Object> hints) {
				return parts.next();
			}
		};
	}

}
