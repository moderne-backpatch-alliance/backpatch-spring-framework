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

package org.springframework.remoting.httpinvoker;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.testfixture.beans.ITestBean;
import org.springframework.beans.testfixture.beans.TestBean;
import org.springframework.remoting.support.RemoteInvocation;
import org.springframework.remoting.support.RemoteInvocationResult;
import org.springframework.web.testfixture.servlet.MockHttpServletRequest;
import org.springframework.web.testfixture.servlet.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIOException;

/**
 * Regression tests for CVE-2016-1000027: the HTTP invoker SERVER path must not run Java
 * deserialization on a remote caller's bytes.
 *
 * <p>These assert the removal of a capability rather than the rejection of one payload, so
 * they carry no gadget chain. {@link DeserializationProbe} records whether {@code readObject()}
 * ran at all; if the stream is deserialized, an attacker's choice of type has already been
 * instantiated and any assertion about the resulting object is beside the point.
 *
 * <p>Measured on the unpatched v5.3.39 baseline, the first test fails and the exception reads
 * "Deserialized object needs to be assignable to type [RemoteInvocation]:
 * ...HttpInvokerDeserializationGuardTests$DeserializationProbe", naming the probe the JVM had
 * already constructed.
 *
 * <p>The CLIENT path ({@code AbstractHttpInvokerRequestExecutor}) is covered too, since
 * upstream's 6.0 removal took the client classes with it. There the untrusted bytes are a
 * server's response, so the server chooses which types this client instantiates.
 *
 * <p>Two of these tests are structural on purpose. Each exporter must DECLARE its own guard
 * rather than inherit one, because the inherited method ships in a different artifact
 * (spring-context) and a consumer who replaces only this one resolves that artifact
 * elsewhere. Asserting behaviour cannot see that boundary: every class here is on one
 * classpath at test time, so an inherited guard and a declared one are indistinguishable.
 *
 * @author Moderne Backpatch Alliance
 */
@SuppressWarnings("deprecation")
class HttpInvokerDeserializationGuardTests {

	@BeforeEach
	void resetProbe() {
		DeserializationProbe.deserialized = false;
	}

	@Test
	void serviceExporterRefusesToDeserializeRequestBody() throws Exception {
		HttpInvokerServiceExporter exporter = new HttpInvokerServiceExporter();
		exporter.setServiceInterface(ITestBean.class);
		exporter.setService(new TestBean("myname", 99));
		exporter.afterPropertiesSet();

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContent(serialize(new DeserializationProbe()));
		MockHttpServletResponse response = new MockHttpServletResponse();

		assertThatIOException()
				.isThrownBy(() -> exporter.handleRequest(request, response))
				.withMessageContaining("CVE-2016-1000027");
		assertThat(DeserializationProbe.deserialized)
				.as("readObject() must not run on a request body supplied by a remote caller")
				.isFalse();
	}

	@Test
	void serviceExporterDeclaresItsOwnGuard() throws Exception {
		assertGuardIsDeclaredBy(HttpInvokerServiceExporter.class, new HttpInvokerServiceExporter());
	}

	@Test
	void simpleServiceExporterDeclaresItsOwnGuard() throws Exception {
		assertGuardIsDeclaredBy(SimpleHttpInvokerServiceExporter.class, new SimpleHttpInvokerServiceExporter());
	}

	@Test
	void clientRequestExecutorRefusesToDeserializeTheResponse() throws Exception {
		StubExecutor executor = new StubExecutor();
		byte[] responseBody = serialize(new DeserializationProbe());

		assertThatIOException()
				.isThrownBy(() -> executor.readResult(new ByteArrayInputStream(responseBody)))
				.withMessageContaining("CVE-2016-1000027");
		assertThat(DeserializationProbe.deserialized)
				.as("readObject() must not run on a response body supplied by a remote server")
				.isFalse();
	}

	/**
	 * The guard has to be DECLARED by the exporter in this artifact, not inherited from
	 * {@code RemoteInvocationSerializingExporter} in spring-context. A consumer who replaces
	 * spring-web alone resolves spring-context from wherever it already came from, and an
	 * inherited guard is then simply not on the classpath.
	 */
	private void assertGuardIsDeclaredBy(Class<?> exporterType, Object exporter) throws Exception {
		Method guard = null;
		try {
			guard = exporterType.getDeclaredMethod("createObjectInputStream", InputStream.class);
		}
		catch (NoSuchMethodException ex) {
			// fall through to the assertion below, which reports the reason
		}
		assertThat(guard)
				.as("%s must declare createObjectInputStream itself, so the sink is dead in this "
						+ "artifact rather than only in the one it inherits from", exporterType.getSimpleName())
				.isNotNull();

		guard.setAccessible(true);
		Method invoked = guard;
		byte[] requestBody = serialize(new DeserializationProbe());
		assertThatExceptionOfType(InvocationTargetException.class)
				.isThrownBy(() -> invoked.invoke(exporter, new ByteArrayInputStream(requestBody)))
				.withCauseInstanceOf(IOException.class)
				.withStackTraceContaining("CVE-2016-1000027");
		assertThat(DeserializationProbe.deserialized)
				.as("readObject() must not run on a request body supplied by a remote caller")
				.isFalse();
	}

	@Test
	void writingInvocationsIsUnaffected() throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		new StubExecutor().writeInvocation(
				new RemoteInvocation("getName", new Class<?>[0], new Object[0]), baos);

		assertThat(baos.size())
				.as("only the server read direction is disabled; serialization still works")
				.isGreaterThan(0);
	}

	private static byte[] serialize(Object obj) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
			oos.writeObject(obj);
		}
		return baos.toByteArray();
	}

	/** Records that deserialization actually ran, which is the capability under test. */
	@SuppressWarnings("serial")
	static class DeserializationProbe implements Serializable {

		static boolean deserialized;

		private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
			ois.defaultReadObject();
			deserialized = true;
		}
	}

	/** Exposes the protected read and write paths; never performs a request. */
	private static class StubExecutor extends AbstractHttpInvokerRequestExecutor {

		@Override
		protected RemoteInvocationResult doExecuteRequest(
				HttpInvokerClientConfiguration config, ByteArrayOutputStream baos) {
			throw new UnsupportedOperationException("not used by these tests");
		}

		void writeInvocation(RemoteInvocation invocation, ByteArrayOutputStream baos) throws IOException {
			writeRemoteInvocation(invocation, baos);
		}

		RemoteInvocationResult readResult(InputStream is) throws IOException, ClassNotFoundException {
			return readRemoteInvocationResult(is, null);
		}
	}

}
