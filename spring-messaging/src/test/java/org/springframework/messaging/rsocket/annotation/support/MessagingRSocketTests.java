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

package org.springframework.messaging.rsocket.annotation.support;

import io.rsocket.Payload;
import io.rsocket.RSocket;
import io.rsocket.util.ByteBufPayload;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.messaging.rsocket.MetadataExtractor;
import org.springframework.messaging.rsocket.RSocketRequester;
import org.springframework.messaging.rsocket.RSocketStrategies;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.MimeTypeUtils;
import org.springframework.util.SimpleRouteMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

class MessagingRSocketTests {

	@Test
	void payloadIsReleasedWhenItsMetadataCannotBeRead() {
		MetadataExtractor failingExtractor = (payload, mimeType) -> {
			throw new IllegalStateException("unreadable metadata");
		};
		RSocketStrategies strategies = RSocketStrategies.create();
		RSocketRequester requester = RSocketRequester.wrap(new RSocket() {},
				MimeTypeUtils.TEXT_PLAIN, MimeTypeUtils.TEXT_PLAIN, strategies);
		MessagingRSocket rsocket = new MessagingRSocket(MimeTypeUtils.TEXT_PLAIN, MimeTypeUtils.TEXT_PLAIN,
				failingExtractor, requester, message -> Mono.empty(), new SimpleRouteMatcher(new AntPathMatcher()),
				strategies);
		Payload payload = ByteBufPayload.create("data", "metadata");

		assertThatIllegalStateException().isThrownBy(() -> rsocket.fireAndForget(payload));
		assertThat(payload.refCnt()).isZero();
	}

}
