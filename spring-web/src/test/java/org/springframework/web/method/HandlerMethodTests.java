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

package org.springframework.web.method;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;

import org.springframework.core.MethodParameter;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link HandlerMethod}'s discovery of parameter annotations declared
 * on an interface method, which is what {@code isOverrideFor} decides.
 *
 * <p>Regression coverage for CVE-2025-41249: before the fix, an interface method
 * whose parameter type is still an unresolved generic at the declaring class was
 * not recognised as being overridden, so annotations declared on it were never
 * merged into the handler method's parameters.
 *
 * @author Peter Streef
 */
class HandlerMethodTests {

	@Test
	void findsParameterAnnotationDeclaredOnInterfaceMethodWithUnresolvedGeneric() {
		// GenericAbstractSuperclass.processOneAndTwo(Long, C) overrides
		// GenericInterface.processOneAndTwo(A, B); 'C' is an unresolved generic,
		// for which ResolvableType.resolve() returns null.
		MethodParameter parameter = parameterOf("processOneAndTwo", 1, Long.class, Object.class);

		assertThat(parameter.getParameterAnnotation(ParamMarker.class)).isNotNull();
	}

	@Test
	void findsParameterAnnotationDeclaredOnInterfaceMethodWithResolvedGeneric() {
		// The control: 'A' resolves to Long at GenericAbstractSuperclass, so this
		// parameter was already found before the fix and must stay found after it.
		MethodParameter parameter = parameterOf("processOne", 0, Long.class);

		assertThat(parameter.getParameterAnnotation(ParamMarker.class)).isNotNull();
	}

	private static MethodParameter parameterOf(String methodName, int index, Class<?>... parameterTypes) {
		Object target = new GenericInterfaceImpl();
		Method method = ClassUtils.getMethod(target.getClass(), methodName, parameterTypes);
		return new HandlerMethod(target, method).getMethodParameters()[index];
	}


	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	@interface ParamMarker {
	}

	interface GenericInterface<A, B> {

		void processOne(@ParamMarker A value1);

		void processOneAndTwo(A value1, @ParamMarker B value2);
	}

	abstract static class GenericAbstractSuperclass<C> implements GenericInterface<Long, C> {

		@Override
		public void processOne(Long value1) {
		}

		@Override
		public void processOneAndTwo(Long value1, C value2) {
		}
	}

	static class GenericInterfaceImpl extends GenericAbstractSuperclass<String> {
		// The compiler does not require a concrete processOneAndTwo(Long, String)
		// here, and we intentionally do not declare one.
	}

}
