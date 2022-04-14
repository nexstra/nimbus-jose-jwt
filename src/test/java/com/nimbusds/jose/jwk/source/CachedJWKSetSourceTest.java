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


import java.lang.Thread.State;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.log.CachingJWKSetSourceLogger;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.cache.CachedObject;

public class CachedJWKSetSourceTest extends AbstractDelegateSourceTest {

	private Runnable lockRunnable = new Runnable() {
		@Override
		public void run() {
			if (!source.getLock().tryLock()) {
				throw new RuntimeException();
			}
		}
	};

	private Runnable unlockRunnable = new Runnable() {
		@Override
		public void run() {
			source.getLock().unlock();
		}
	};
	
	private CachingJWKSetSource<SecurityContext, CachingJWKSetSource.Listener<SecurityContext>> source;

	private CachingJWKSetSource.Listener<SecurityContext> listener = new CachingJWKSetSourceLogger<>(Level.INFO);

	@Before
	public void setUp() throws Exception {
		super.setUp();
		source = new CachingJWKSetSource<>(delegate, 10 * 3600 * 1000, 2 * 1000, listener);
	}

	@Test
	public void testShouldUseDelegateWhenNotCached() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);
	}

	@Test
	public void testShouldUseCachedValue() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new RuntimeException("TEST!", null));
		source.getJWKSet(false, System.currentTimeMillis(), context);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);
		verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldUseDelegateWhenExpiredCache() throws Exception {
		JWKSet first = new JWKSet(jwk);
		JWKSet second = new JWKSet(Arrays.asList(jwk, jwk));

		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		source.getJWKSet(false, System.currentTimeMillis(), context);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), first);
		verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());

		// second
		source.getJWKSet(false, CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), second);
		verify(delegate, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldNotReturnExpiredValueWhenExpiredCache() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST!", null));
		source.getJWKSet(false, System.currentTimeMillis(), context);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);

		try {
			source.getJWKSet(false, CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context);
			fail();
		} catch(JWKSetUnavailableException e) {
			// pass
		}
	}

	@Test
	public void testShouldUseCachedValueForKnownKey() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST!", null));
		JWKSetBasedJWKSource<SecurityContext> wrapper = new JWKSetBasedJWKSource<>(source);
		try {
			JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().keyID(KID).build());
	
			List<JWK> list = wrapper.get(selector, context);
			assertEquals(Arrays.asList(jwk), list);
			verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());
		} finally {
			wrapper.close();
		}
	}

	@Test
	public void testShouldGetBaseProvider() {
		assertThat(source.getSource(), equalTo(delegate));
	}

	@Test
	public void testShouldRefreshCacheForUnknownKey() throws Exception {
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		JWKSetBasedJWKSource<SecurityContext> wrapper = new JWKSetBasedJWKSource<>(source);
		try {
			// first
			assertEquals(wrapper.get(aSelector, context), first.getKeys());
			verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());
	
			Thread.sleep(1); // cache is not refreshed if request timestamp is >= timestamp parameter
			
			// second
			assertEquals(wrapper.get(bSelector, context), second.getKeys());
			verify(delegate, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
		} finally {
			wrapper.close();
		}
	}

	@Test
	public void testShouldRefreshCacheAndReturnEmptyForUnknownKey() throws Exception {
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		JWKSetBasedJWKSource<SecurityContext> wrapper = new JWKSetBasedJWKSource<>(source);
		try {
			// first
			assertEquals(wrapper.get(aSelector, context), first.getKeys());
			verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());
	
			Thread.sleep(1);
			
			// second
			assertEquals(wrapper.get(cSelector, context), Collections.emptyList());
			verify(delegate, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
		} finally {
			wrapper.close();
		}
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
				source.getJWKSet(false, System.currentTimeMillis(), context);
				fail();
			} catch(JWKSetUnavailableException e) {
				// pass
			}
		} finally {
			helper.close();
		}
	}

	@Test
	public void testShouldAcceptIfAnotherThreadUpdatesCache() throws Exception {
		Runnable racer = new Runnable() {
			@Override
			public void run() {
				try {
					Thread.sleep(1000);
					source.getJWKSet(false, System.currentTimeMillis(), context);
				} catch (Exception e) {
					throw new RuntimeException();
				}
			}
		};

		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);

		ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(racer).addRun(unlockRunnable);
		try {
			helper.begin();

			helper.next();

			source.getJWKSet(false, System.currentTimeMillis(), context);

			verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());
		} finally {
			helper.close();
		}
	}
}
