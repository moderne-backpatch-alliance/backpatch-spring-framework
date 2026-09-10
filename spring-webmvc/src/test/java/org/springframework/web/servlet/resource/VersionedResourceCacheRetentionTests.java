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

package org.springframework.web.servlet.resource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.util.DigestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression tests for CVE-2026-41842.
 *
 * <p>A request path may carry the correct content version token more than once.
 * {@code extractVersion} takes the substring after the LAST {@code '-'}, so it
 * still reports the correct version; before the fix {@code removeVersion}
 * deleted EVERY occurrence, so all such paths collapsed to the same base file
 * and resolved successfully. {@link CachingResourceResolver} caches every
 * successful resolution under the request path, in a cache that by default is
 * an unbounded {@link ConcurrentMapCache}, so one publicly known version string
 * yielded unlimited distinct cache entries.
 *
 * @author Backpatch Alliance
 */
class VersionedResourceCacheRetentionTests {

	private static final int DISTINCT_PATHS = 50;


	@Test
	public void repeatedVersionTokensDoNotEachOccupyTheResourceCache(@TempDir Path dir) throws Exception {
		Fixture f = new Fixture(dir);

		for (int tokens = 1; tokens <= DISTINCT_PATHS; tokens++) {
			f.resolve(f.pathWithVersionRepeated(tokens));
		}

		// only the canonical single-token path is a real resource, so only it may be retained
		assertThat(f.cache.getNativeCache().size())
				.as("entries retained in the resource cache for %d attacker-chosen paths", DISTINCT_PATHS)
				.isEqualTo(1);
	}

	@Test
	public void theCanonicalVersionedPathStillResolves(@TempDir Path dir) throws Exception {
		Fixture f = new Fixture(dir);

		assertThat(f.resolve(f.pathWithVersionRepeated(1))).isNotNull();
		assertThat(f.resolve("app.css")).isNotNull();
	}


	private static final class Fixture {

		private final String version;

		private final List<Resource> locations;

		private final ConcurrentMapCache cache = new ConcurrentMapCache("test");

		private final List<ResourceResolver> resolvers;

		Fixture(Path dir) throws Exception {
			byte[] body = "body { color: red; }".getBytes(StandardCharsets.UTF_8);
			Files.write(dir.resolve("app.css"), body);
			this.version = DigestUtils.md5DigestAsHex(body);
			this.locations = Collections.singletonList(new FileSystemResource(dir.toString() + "/"));
			this.resolvers = Arrays.asList(
					new CachingResourceResolver(this.cache),
					new VersionResourceResolver().addVersionStrategy(new ContentVersionStrategy(), "/**"),
					new PathResourceResolver());
		}

		String pathWithVersionRepeated(int times) {
			StringBuilder path = new StringBuilder("app");
			for (int i = 0; i < times; i++) {
				path.append('-').append(this.version);
			}
			return path.append(".css").toString();
		}

		Resource resolve(String requestPath) {
			return new DefaultResourceResolverChain(this.resolvers).resolveResource(null, requestPath, this.locations);
		}
	}

}
