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

package org.springframework.beans;

import org.junit.Test;

import org.springframework.core.OverridingClassLoader;
import org.springframework.core.io.DefaultResourceLoader;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

/**
 * Regression tests for CVE-2022-22965 (Spring4Shell) at the 5.1.20.RELEASE baseline.
 *
 * <p>Data binding walks {@code PropertyDescriptor} paths. Before the fix, the only
 * properties withheld from a {@code Class} target were the two named {@code classLoader}
 * and {@code protectionDomain}, so any other {@code Class} property remained a legal
 * step in a binding path — on JDK 9+ that includes {@code getModule()}, from which
 * {@code class.module.classLoader} reaches a ClassLoader again and the published exploit
 * rewrites Tomcat's access log to drop a web shell.
 *
 * <p>The fix inverts the rule: under a {@code Class} target only the name variants are
 * bindable, so the traversal has nowhere to go regardless of which JDK is underneath.
 * These tests assert that inversion in the form that is observable on JDK 8, which is
 * what this baseline compiles against; {@code getModule()} does not exist there, so the
 * exploit's own path cannot be expressed as a test at this toolchain.
 *
 * @see <a href="https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement">
 * Spring Framework RCE, early announcement</a>
 */
public class CachedIntrospectionResultsClassPropertyTests {

	@Test
	public void classPackageIsNotBindable() {
		assertFalse(new BeanWrapperImpl(new Target()).isReadableProperty("class.package"));
	}

	@Test
	public void classSuperclassIsNotBindable() {
		assertFalse(new BeanWrapperImpl(new Target()).isReadableProperty("class.superclass"));
	}

	@Test
	public void classLoaderAndProtectionDomainStayUnreachableUnderClass() {
		BeanWrapperImpl accessor = new BeanWrapperImpl(new Target());
		assertFalse(accessor.isReadableProperty("class.classLoader"));
		assertFalse(accessor.isReadableProperty("class.protectionDomain"));
	}

	@Test
	public void classNameVariantsRemainReadable() {
		BeanWrapperImpl accessor = new BeanWrapperImpl(new Target());
		assertTrue(accessor.isReadableProperty("class.name"));
		assertTrue(accessor.isReadableProperty("class.simpleName"));
		assertTrue(accessor.isReadableProperty("class.canonicalName"));
	}

	/**
	 * The first cut of the fix withheld every ClassLoader-typed property, which broke
	 * ordinary beans that expose a writable one. Upstream restored those in 5.2.21;
	 * without that follow-up this test fails with NotWritablePropertyException.
	 */
	@Test
	public void writableClassLoaderPropertyRemainsBindable() {
		BeanWrapperImpl accessor = new BeanWrapperImpl(new DefaultResourceLoader());
		assertTrue(accessor.isReadableProperty("classLoader"));
		assertTrue(accessor.isWritableProperty("classLoader"));
		OverridingClassLoader replacement = new OverridingClassLoader(getClass().getClassLoader());
		accessor.setPropertyValue("classLoader", replacement);
		assertSame(replacement, accessor.getPropertyValue("classLoader"));
	}


	public static class Target {

		private String name;

		public String getName() {
			return this.name;
		}

		public void setName(String name) {
			this.name = name;
		}
	}

}
