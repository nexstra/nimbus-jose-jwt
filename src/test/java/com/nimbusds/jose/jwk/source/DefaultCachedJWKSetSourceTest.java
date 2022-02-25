/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2022, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.nimbusds.jose.jwk.source;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.Before;
import org.junit.Test;

import java.lang.Thread.State;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.only;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DefaultCachedJWKSetSourceTest extends AbstractDelegateSourceTest {

	private Runnable lockRunnable = new Runnable() {
		@Override
		public void run() {
			if (!provider.getLock().tryLock()) {
				throw new RuntimeException();
			}
		}
	};

	private Runnable unlockRunnable = new Runnable() {
		@Override
		public void run() {
			provider.getLock().unlock();
		}
	};

	private DefaultCachedJWKSetSource provider;

	@Before
	public void setUp() throws Exception {
		super.setUp();
		provider = new DefaultCachedJWKSetSource(delegate, 10 * 3600 * 1000, 2 * 1000);
	}

	@Test
	public void testShouldUseDelegateWhenNotCached() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false))).thenReturn(jwks);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false), jwks);
	}

	@Test
	public void testShouldUseCachedValue() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false))).thenReturn(jwks).thenThrow(new RuntimeException("TEST!", null));
		provider.getJWKSet(System.currentTimeMillis(), false);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false), jwks);
		verify(delegate, only()).getJWKSet(anyLong(), eq(false));
	}

	@Test
	public void testShouldUseDelegateWhenExpiredCache() throws Exception {
		JWKSet first = new JWKSet(jwk);
		JWKSet second = new JWKSet(Arrays.asList(jwk, jwk));

		when(delegate.getJWKSet(anyLong(), eq(false))).thenReturn(first).thenReturn(second);

		// first
		provider.getJWKSet(System.currentTimeMillis(), false);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false), first);
		verify(delegate, only()).getJWKSet(anyLong(), eq(false));

		// second
		provider.getJWKSet(provider.getExpires(System.currentTimeMillis() + 1), false);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false), second);
		verify(delegate, times(2)).getJWKSet(anyLong(), eq(false));
	}

	@Test
	public void testShouldNotReturnExpiredValueWhenExpiredCache() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false))).thenReturn(jwks).thenThrow(new JWKSetUnavailableException("TEST!", null));
		provider.getJWKSet(System.currentTimeMillis(), false);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false), jwks);

		try {
			provider.getJWKSet(provider.getExpires(System.currentTimeMillis() + 1), false);
			fail();
		} catch(JWKSetUnavailableException e) {
			// pass
		}
	}

	@Test
	public void testShouldUseCachedValueForKnownKey() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false))).thenReturn(jwks).thenThrow(new JWKSetUnavailableException("TEST!", null));
		UrlJWKSource wrapper = new UrlJWKSource(provider);
		JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyID(KID).build());

		List<JWK> list = wrapper.get(selector, null);
		assertEquals(Arrays.asList(jwk), list);
		verify(delegate, only()).getJWKSet(anyLong(), eq(false));
	}

	@Test
	public void testShouldGetBaseProvider() throws Exception {
		assertThat(provider.getSource(), equalTo(delegate));
	}

	@Test
	public void testShouldRefreshCacheForUnknownKey() throws Exception {
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(Arrays.asList(b));

		when(delegate.getJWKSet(anyLong(), eq(false))).thenReturn(first).thenReturn(second);

		UrlJWKSource wrapper = new UrlJWKSource(provider);

		// first
		assertEquals(wrapper.get(aSelector, null), first.getKeys());
		verify(delegate, only()).getJWKSet(anyLong(), eq(false));

		Thread.sleep(1); // cache is not refreshed if request timestamp is >= timestamp parameter
		
		// second
		assertEquals(wrapper.get(bSelector, null), second.getKeys());
		verify(delegate, times(2)).getJWKSet(anyLong(), eq(false));
	}

	@Test
	public void testShouldRefreshCacheAndReturnEmptyForUnknownKey() throws Exception {
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(Arrays.asList(b));

		when(delegate.getJWKSet(anyLong(), eq(false))).thenReturn(first).thenReturn(second);

		UrlJWKSource wrapper = new UrlJWKSource(provider);

		// first
		assertEquals(wrapper.get(aSelector, null), first.getKeys());
		verify(delegate, only()).getJWKSet(anyLong(), eq(false));

		Thread.sleep(1);
		
		// second
		assertEquals(wrapper.get(cSelector, null), Collections.emptyList());
		verify(delegate, times(2)).getJWKSet(anyLong(), eq(false));
	}

	@Test
	public void testShouldThrowExceptionIfAnotherThreadBlocksUpdate() throws Exception {
		ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(unlockRunnable);
		try {
			helper.start();
			while (helper.getState() != State.WAITING) {
				Thread.yield();
			}

			try {
				provider.getJWKSet(System.currentTimeMillis(), false);
				fail();
			} catch(JWKSetUnavailableException e) {
				// pass
			}
		} finally {
			helper.close();
		}
	}

	@Test
	public void testShouldAccceptIfAnotherThreadUpdatesCache() throws Exception {
		Runnable racer = new Runnable() {
			@Override
			public void run() {
				try {
					Thread.sleep(1000);
					provider.getJWKSet(System.currentTimeMillis(), false);
				} catch (Exception e) {
					throw new RuntimeException();
				}
			}
		};

		when(delegate.getJWKSet(anyLong(), eq(false))).thenReturn(jwks);

		ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(racer).addRun(unlockRunnable);
		try {
			helper.begin();

			helper.next();

			provider.getJWKSet(System.currentTimeMillis(), false);

			verify(delegate, only()).getJWKSet(anyLong(), eq(false));
		} finally {
			helper.close();
		}
	}
}
