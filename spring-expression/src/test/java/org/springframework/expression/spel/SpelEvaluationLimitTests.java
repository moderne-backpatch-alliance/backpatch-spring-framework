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

package org.springframework.expression.spel;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Regression tests for the SpEL denial-of-service backpatches at 5.3.39:
 * CVE-2026-41849 (integer overflow in string repetition), CVE-2026-41850
 * (algorithmic DoS via the operation budget) and CVE-2026-41851 (eager
 * inline-collection construction now built lazily under the budget).
 *
 * <p>Each CVE has one fail-before method -- it fails when the corresponding
 * production hunk is reverted -- and one positive control that behaves the same
 * before and after the fix. The fail-before methods are written so the reverted
 * baseline throws a different exception or none at all, never an
 * {@link OutOfMemoryError}, so the fail-before control run stays stable.
 */
class SpelEvaluationLimitTests {

	private final SpelExpressionParser parser = new SpelExpressionParser();

	private final StandardEvaluationContext context = new StandardEvaluationContext();


	// CVE-2026-41849: text.length() * count overflowed int and slipped past the
	// 256-char limit. This is upstream's own overflow probe from OperatorTests
	// .stringRepeat(): 2 * ((Integer.MAX_VALUE / 2) + 1) overflows int to a
	// negative value. The reverted baseline passes the (int) `> 256` check on the
	// negative product and then throws NegativeArraySizeException from
	// new StringBuilder(negative) -- a DIFFERENT exception -- so this asserts the
	// fix's SpelEvaluationException and fails before it without ever allocating.
	//
	// The positive-overflow case that actually OOMs ('xxxx' * 1073741824, whose
	// product wraps to a small non-negative value) is deliberately NOT asserted,
	// here or upstream: any int-overflowing count is in the billions, so the
	// reverted append loop OOMs the fail-before control rather than throwing. That
	// vector is verified manually (baseline OOM ~399ms -> patched throw ~13ms);
	// see patch 0016. The long-arithmetic check closes both landings.
	@Test
	void stringRepetitionIntegerOverflowIsRejected() {
		int repeatCount = (Integer.MAX_VALUE / 2) + 1;
		assertThat(2 * repeatCount).isNegative();
		Expression expression = this.parser.parseExpression("'ab' * " + repeatCount);
		assertThatExceptionOfType(SpelEvaluationException.class)
				.isThrownBy(() -> expression.getValue(this.context))
				.satisfies(ex -> assertThat(ex.getMessageCode())
						.isEqualTo(SpelMessage.MAX_REPEATED_TEXT_SIZE_EXCEEDED));
	}

	// Upstream (6.2.19) throws NEGATIVE_REPEATED_TEXT_COUNT for a negative count;
	// that SpelMessage does not exist at 5.3.39, so the overflow-safe check folds a
	// negative count into MAX_REPEATED_TEXT_SIZE_EXCEEDED via its `result < 0`
	// branch (see patch 0016). Fail-before: the reverted baseline passes the (int)
	// `> 256` check on -1 and throws NegativeArraySizeException from
	// new StringBuilder(-1), a different exception, so this fails before the fix.
	@Test
	void stringRepetitionWithNegativeCountIsRejected() {
		Expression expression = this.parser.parseExpression("'a' * -1");
		assertThatExceptionOfType(SpelEvaluationException.class)
				.isThrownBy(() -> expression.getValue(this.context))
				.satisfies(ex -> assertThat(ex.getMessageCode())
						.isEqualTo(SpelMessage.MAX_REPEATED_TEXT_SIZE_EXCEEDED));
	}

	@Test
	void stringRepetitionWithinLimitIsUnaffected() {
		Expression expression = this.parser.parseExpression("'ab' * 3");
		assertThat(expression.getValue(this.context)).isEqualTo("ababab");
	}

	// CVE-2026-41850: without the operation budget a projection over a large
	// collection performs unbounded work. Projecting over 20000 elements exceeds
	// the 10000-operation default, so the fixed build throws
	// MAX_OPERATIONS_EXCEEDED; the reverted build (no trackOperation in
	// Projection) simply returns the 20000-element result and this fails before.
	@Test
	void projectionExceedingOperationBudgetIsRejected() {
		Expression expression = this.parser.parseExpression("(new int[20000]).![#this]");
		assertThatExceptionOfType(SpelEvaluationException.class)
				.isThrownBy(() -> expression.getValue(this.context))
				.satisfies(ex -> assertThat(ex.getMessageCode())
						.isEqualTo(SpelMessage.MAX_OPERATIONS_EXCEEDED));
	}

	@Test
	void projectionWithinOperationBudgetIsUnaffected() {
		Expression expression = this.parser.parseExpression("{1,2,3,4,5}.![#this + 1]");
		assertThat(expression.getValue(this.context)).isEqualTo(Arrays.asList(2, 3, 4, 5, 6));
	}

	// CVE-2026-41851: the inline collection constant was built eagerly in the
	// constructor and returned from getValueInternal without touching the budget.
	// With a maxOperations of 5, evaluating a 10-element inline list now trips the
	// budget because createList tracks one operation per element; the reverted
	// (eager) build returns the cached constant untracked and this fails before.
	@Test
	void inlineListMaterializationIsBudgeted() {
		SpelParserConfiguration configuration = new SpelParserConfiguration(
				SpelCompilerMode.OFF, null, false, false, 0, 10_000, 5);
		Expression expression = new SpelExpressionParser(configuration)
				.parseExpression("{1,2,3,4,5,6,7,8,9,10}");
		assertThatExceptionOfType(SpelEvaluationException.class)
				.isThrownBy(() -> expression.getValue(this.context))
				.satisfies(ex -> assertThat(ex.getMessageCode())
						.isEqualTo(SpelMessage.MAX_OPERATIONS_EXCEEDED));
	}

	@Test
	void smallInlineListIsUnaffected() {
		Expression expression = this.parser.parseExpression("{1,2,3}");
		assertThat(expression.getValue(this.context)).isEqualTo(Arrays.asList(1, 2, 3));
	}

	// CVE-2026-41851: the shared regex pattern cache was an unbounded ConcurrentHashMap
	// living on the parsed expression, so an application that CACHES a parsed expression and
	// feeds it attacker-chosen regexes grows the cache without bound -- the advisory's
	// "unbounded cache growth ... typically requiring millions of evaluations, even when
	// utilizing a single expression with dynamic inputs". Upstream 6.2.19 replaced it with a
	// ConcurrentLruCache bounded at OperatorMatches.MAX_PATTERN_CACHE_SIZE (256).
	//
	// The size is read reflectively and 256 is spelled out rather than referenced, so the
	// method still COMPILES against a tree with the production hunk reverted -- where the
	// field is the old ConcurrentMap and the assertion then fails on 1000 entries. Both the
	// new constant and the enforcement live in OperatorMatches.java, so a fail_before_keep
	// entry could not have separated them.
	@Test
	void regexPatternCacheIsBounded() throws Exception {
		Expression expression = this.parser.parseExpression("#s matches #r");
		this.context.setVariable("s", "abc");
		for (int i = 0; i < 1000; i++) {
			this.context.setVariable("r", "a" + i + "bc.*");
			expression.getValue(this.context, Boolean.class);
		}
		assertThat(patternCacheSize(expression)).isLessThanOrEqualTo(256);
	}

	@Test
	void matchesOperatorIsUnaffected() {
		this.context.setVariable("s", "abc");
		this.context.setVariable("r", "a.c");
		Expression expression = this.parser.parseExpression("#s matches #r");
		assertThat(expression.getValue(this.context, Boolean.class)).isTrue();
	}

	@Test
	void overlongRegexIsStillRejected() {
		this.context.setVariable("s", "abc");
		this.context.setVariable("r", repeat("a", 1001));
		Expression expression = this.parser.parseExpression("#s matches #r");
		assertThatExceptionOfType(SpelEvaluationException.class)
				.isThrownBy(() -> expression.getValue(this.context, Boolean.class))
				.satisfies(ex -> assertThat(ex.getMessageCode())
						.isEqualTo(SpelMessage.MAX_REGEX_LENGTH_EXCEEDED));
	}

	// CVE-2026-41850, the half the operation budget did not reach until this backpatch:
	// indexing a non-List Collection walks the iterator to the requested position, so a
	// 22-character expression performs work proportional to the collection rather than to
	// its own length. Untracked, a 20000-element walk costs one operation; tracked, it costs
	// 20000 and trips the 10000 default. Fail-before: with the Indexer hunk reverted this
	// returns 19999 instead of throwing.
	@Test
	void collectionIndexingExceedsOperationBudget() {
		this.context.setVariable("big", sequence(20_000));
		Expression expression = this.parser.parseExpression("#big[19999]");
		assertThatExceptionOfType(SpelEvaluationException.class)
				.isThrownBy(() -> expression.getValue(this.context))
				.satisfies(ex -> assertThat(ex.getMessageCode())
						.isEqualTo(SpelMessage.MAX_OPERATIONS_EXCEEDED));
	}

	@Test
	void smallCollectionIndexingIsUnaffected() {
		this.context.setVariable("small", sequence(10));
		Expression expression = this.parser.parseExpression("#small[7]");
		assertThat(expression.getValue(this.context)).isEqualTo(7);
	}

	// CVE-2026-41850, the property-access half. A 6000-element projection costs 6000 tracked
	// operations on its own, which is inside the 10000 budget; each element additionally reads
	// a property, and only with the PropertyOrFieldReference hunk does that second 6000 count.
	// Fail-before: with that hunk reverted the total stays at 6000 and this completes.
	@Test
	void propertyAccessExceedsOperationBudget() {
		StandardEvaluationContext rootContext = new StandardEvaluationContext(new Named("spring"));
		Expression expression = this.parser.parseExpression("(new int[6000]).![#root.name]");
		assertThatExceptionOfType(SpelEvaluationException.class)
				.isThrownBy(() -> expression.getValue(rootContext))
				.satisfies(ex -> assertThat(ex.getMessageCode())
						.isEqualTo(SpelMessage.MAX_OPERATIONS_EXCEEDED));
	}

	@Test
	void propertyAccessWithinOperationBudgetIsUnaffected() {
		StandardEvaluationContext rootContext = new StandardEvaluationContext(new Named("spring"));
		Expression expression = this.parser.parseExpression("#root.name");
		assertThat(expression.getValue(rootContext)).isEqualTo("spring");
	}


	private static Set<Integer> sequence(int size) {
		Set<Integer> values = new LinkedHashSet<>();
		for (int i = 0; i < size; i++) {
			values.add(i);
		}
		return values;
	}

	private static String repeat(String text, int count) {
		StringBuilder builder = new StringBuilder(text.length() * count);
		for (int i = 0; i < count; i++) {
			builder.append(text);
		}
		return builder.toString();
	}

	private static int patternCacheSize(Expression expression) throws Exception {
		Field astField = SpelExpression.class.getDeclaredField("ast");
		astField.setAccessible(true);
		Object ast = astField.get(expression);
		Field cacheField = ast.getClass().getDeclaredField("patternCache");
		cacheField.setAccessible(true);
		Object cache = cacheField.get(ast);
		return (int) cache.getClass().getMethod("size").invoke(cache);
	}


	static class Named {

		private final String name;

		Named(String name) {
			this.name = name;
		}

		public String getName() {
			return this.name;
		}
	}

}
