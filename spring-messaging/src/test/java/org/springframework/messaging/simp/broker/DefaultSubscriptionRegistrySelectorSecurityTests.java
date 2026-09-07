/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.messaging.simp.broker;

import org.junit.Before;
import org.junit.Test;

import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.util.MultiValueMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

/**
 * CVE-2018-1270 / CVE-2018-1275: a STOMP SUBSCRIBE frame carries its own SpEL
 * expression in the "selector" native header, and {@code DefaultSubscriptionRegistry}
 * evaluated it against a full {@code StandardEvaluationContext}. That context
 * resolves type references, so a subscriber could reach arbitrary static methods —
 * {@code T(java.lang.Runtime).getRuntime().exec(...)} — from an unauthenticated
 * frame.
 *
 * <p>These tests assert the ATTACKER CAPABILITY is gone rather than that some
 * exception is thrown: each records whether the expression actually reached the
 * target, so they fail against the unpatched registry, which really does invoke it.
 *
 * @author Backpatch Alliance
 */
public class DefaultSubscriptionRegistrySelectorSecurityTests {

	private static volatile boolean invoked;

	private DefaultSubscriptionRegistry registry;


	/** Invoked only if the selector expression can reach a static method. */
	public static boolean markInvoked() {
		invoked = true;
		return true;
	}


	@Before
	public void setup() {
		this.registry = new DefaultSubscriptionRegistry();
		invoked = false;
	}


	@Test
	public void typeReferenceInSelectorIsRefused() {
		String selector = "T(org.springframework.messaging.simp.broker." +
				"DefaultSubscriptionRegistrySelectorSecurityTests).markInvoked()";

		MultiValueMap<String, String> actual = findWithSelector(selector);

		assertFalse("selector reached a static method — T(...) still resolves", invoked);
		assertNotNull(actual);
		assertEquals("subscription matched on an expression that must not evaluate",
				0, actual.size());
	}

	@Test
	public void methodInvocationInSelectorIsRefused() {
		MultiValueMap<String, String> actual =
				findWithSelector("headers.destination.substring(0) != null");

		assertNotNull(actual);
		assertEquals("subscription matched on a method call that must not evaluate",
				0, actual.size());
	}

	@Test
	public void constructorInvocationInSelectorIsRefused() {
		MultiValueMap<String, String> actual =
				findWithSelector("new java.lang.String('x') != null");

		assertNotNull(actual);
		assertEquals("subscription matched on a constructor call that must not evaluate",
				0, actual.size());
	}

	@Test
	public void headerSelectorStillMatches() {
		MultiValueMap<String, String> actual = findWithSelector("headers.foo == 'bar'");

		assertNotNull(actual);
		assertEquals("a legitimate header selector no longer matches", 1, actual.size());
	}


	private MultiValueMap<String, String> findWithSelector(String selector) {
		String sessionId = "sess01";
		String destination = "/foo";

		SimpMessageHeaderAccessor accessor = SimpMessageHeaderAccessor.create(SimpMessageType.SUBSCRIBE);
		accessor.setSessionId(sessionId);
		accessor.setSubscriptionId("subs01");
		accessor.setDestination(destination);
		accessor.setNativeHeader("selector", selector);
		this.registry.registerSubscription(MessageBuilder.createMessage("", accessor.getMessageHeaders()));

		SimpMessageHeaderAccessor headers = SimpMessageHeaderAccessor.create();
		headers.setDestination(destination);
		headers.setNativeHeader("foo", "bar");
		Message<?> message = MessageBuilder.createMessage("", headers.getMessageHeaders());

		return this.registry.findSubscriptions(message);
	}

}
