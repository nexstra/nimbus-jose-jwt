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


import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.log.RefreshAheadCachingJWKSetSourceLogger;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.cache.CachedObject;

public class RefreshAheadCachingJWKSetSourceTest extends AbstractDelegateSourceTest {

	private final Runnable lockRunnable = new Runnable() {
		@Override
		public void run() {
			if (!source.getLazyLock().tryLock()) {
				throw new RuntimeException();
			}
		}
	};

	private final Runnable unlockRunnable = new Runnable() {
		@Override
		public void run() {
			source.getLazyLock().unlock();
		}
	};

	private static final String KID = "NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg";
	protected static final JWKSelector KID_SELECTOR = new JWKSelector(new JWKMatcher.Builder().keyID(KID).build());

	private RefreshAheadCachingJWKSetSource<SecurityContext> source;
	private RefreshAheadCachingJWKSetSource.Listener<SecurityContext> listener = new RefreshAheadCachingJWKSetSourceLogger<SecurityContext>(Level.INFO);
	
	private JWKSetBasedJWKSource<SecurityContext> wrapper;

	@Before
	public void setUp() throws Exception {
		super.setUp();

		source = new RefreshAheadCachingJWKSetSource<>(delegate, 3600 * 1000 * 10, 15 * 1000, 10 * 1000, false, listener);

		wrapper = new JWKSetBasedJWKSource<>(source);
	}
	
	
	@Test
	public void testRejectRefreshAheadTimePlusCacheRefreshTimeoutExceedingTimeToLive() {
		
		long timeToLive = 60_000;
		long cacheRefreshTimeout = 10_000;
		long refreshAheadTime = 50_001;
		
		assertTrue(cacheRefreshTimeout + refreshAheadTime > timeToLive);
		
		try {
			new RefreshAheadCachingJWKSetSource<>(delegate, timeToLive, cacheRefreshTimeout, refreshAheadTime, false, listener);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The sum of the refresh-ahead time (50001ms) and the cache refresh timeout (10000ms) must not exceed the time-to-lived time (60000ms)", e.getMessage());
		}
	}

	@Test
	public void testShouldUseFallbackWhenNotCached() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);
	}

	@Test
	public void testShouldUseCachedValue() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new JWKSetUnavailableException("TEST!", null));
		source.getJWKSet(false, System.currentTimeMillis(), context);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);
		verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldUseFallbackWhenExpiredCache() throws Exception {
		JWKSet first = new JWKSet(jwk);
		JWKSet second = new JWKSet(Arrays.asList(jwk, jwk));

		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), first);
		verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());

		// second
		assertEquals(source.getJWKSet(false, CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context), second);
		verify(delegate, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldNotReturnExpiredValueWhenExpiredCacheAndRefreshFails() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new KeySourceException("TEST!", null));
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);

		try {
			source.getJWKSet(false, CachedObject.computeExpirationTime(System.currentTimeMillis() + 1, source.getTimeToLive()), context);
			fail();
		} catch(KeySourceException e) {
			assertEquals("TEST!", e.getMessage());
		}
	}

	@Test
	public void testShouldGetBaseProvider() {
		assertThat(source.getSource(), equalTo(delegate));
	}

	@Test
	public void testShouldUseCachedValueForKnownKey() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet).thenThrow(new KeySourceException("TEST!", null));
		assertEquals(wrapper.get(KID_SELECTOR, context), Arrays.asList(jwk));
		verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldRefreshCacheForUncachedKnownKey() throws Exception {
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		assertEquals(wrapper.get(aSelector, context), first.getKeys());
		verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());

		Thread.sleep(1);
		
		// second
		assertEquals(wrapper.get(bSelector, context), second.getKeys());
		verify(delegate, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
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

		// first
		assertEquals(wrapper.get(aSelector, context), Arrays.asList(a));
		verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());

		// second
		List<JWK> list = wrapper.get(cSelector, context);
		assertTrue(list.isEmpty());
	}

	@Test
	public void testShouldPreemptivelyRefreshCacheForKeys() throws Exception {
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first jwks
		List<JWK> longBeforeExpiryKeys = wrapper.get(aSelector, context);
		assertFalse(longBeforeExpiryKeys.isEmpty());
		assertEquals(longBeforeExpiryKeys, first.getKeys());
		verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());

		long justBeforeExpiry = CachedObject.computeExpirationTime(System.currentTimeMillis(), source.getTimeToLive()) - TimeUnit.SECONDS.toMillis(5);
		verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());

		JWKSet justBeforeExpiryKeys = source.getJWKSet(false, justBeforeExpiry, context);
		assertFalse(justBeforeExpiryKeys.isEmpty());
		assertEquals(justBeforeExpiryKeys.getKeys(), first.getKeys()); // triggers a preemptive refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);
		verify(delegate, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());

		// second jwks
		assertEquals(wrapper.get(bSelector, context), second.getKeys()); // should already be in cache
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(delegate, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldNotPreemptivelyRefreshCacheIfRefreshAlreadyInProgress() throws Exception {
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first jwks
		assertEquals(wrapper.get(aSelector, context), first.getKeys());
		verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());

		CachedObject<JWKSet> cache = source.getCachedJWKSetIfValid(System.currentTimeMillis());

		long justBeforeExpiry = CachedObject.computeExpirationTime(System.currentTimeMillis(), source.getTimeToLive()) - TimeUnit.SECONDS.toMillis(5);

		assertEquals(source.getJWKSet(false, justBeforeExpiry, context), first); // triggers a preemptive refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		source.refreshAheadOfExpiration(cache, false, justBeforeExpiry, context); // should not trigger a preemptive refresh attempt

		verify(delegate, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());

		// second jwks
		assertEquals(wrapper.get(bSelector, null), second.getKeys()); // should already be in cache
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(delegate, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldFirePreemptivelyRefreshCacheAgainIfPreviousPreemptivelyRefreshAttemptFailed() throws Exception {
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(b);

		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(first).thenThrow(new JWKSetUnavailableException("TEST!")).thenReturn(second);

		// first jwks
		assertEquals(wrapper.get(aSelector, context), first.getKeys());
		verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());

		long justBeforeExpiry = CachedObject.computeExpirationTime(System.currentTimeMillis(), source.getTimeToLive()) - TimeUnit.SECONDS.toMillis(5);

		assertEquals(source.getJWKSet(false, justBeforeExpiry, context), first); // triggers a preemptive refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		assertEquals(source.getJWKSet(false, justBeforeExpiry, context), first); // triggers a another preemptive refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		verify(delegate, times(3)).getJWKSet(eq(false), anyLong(), anySecurityContext());

		// second jwks
		assertEquals(wrapper.get(bSelector, context), second.getKeys()); // should already be in cache
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(delegate, times(3)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldAcceptIfAnotherThreadPreemptivelyUpdatesCache() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);

		source.getJWKSet(false, System.currentTimeMillis(), context);

		long justBeforeExpiry = CachedObject.computeExpirationTime(System.currentTimeMillis(), source.getTimeToLive()) - TimeUnit.SECONDS.toMillis(5);

		ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(unlockRunnable);
		try {
			helper.begin();

			source.getJWKSet(false, justBeforeExpiry, context); // wants to update, but can't get lock

			verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());
		} finally {
			helper.close();
		}
	}

	@Test
	public void testShouldSchedulePreemptivelyRefreshCacheForKeys() throws Exception {
		long timeToLive = 1000; 
		long refreshTimeout = 150;
		long preemptiveRefresh = 300;

		RefreshAheadCachingJWKSetSource<SecurityContext> provider = new RefreshAheadCachingJWKSetSource<>(delegate, timeToLive, refreshTimeout, preemptiveRefresh, true, listener);
		JWKSetBasedJWKSource<SecurityContext> wrapper = new JWKSetBasedJWKSource<>(provider);

		try {
			JWK a = mock(JWK.class);
			when(a.getKeyID()).thenReturn("a");
			JWK b = mock(JWK.class);
			when(b.getKeyID()).thenReturn("b");
	
			JWKSet first = new JWKSet(a);
			JWKSet second = new JWKSet(b);
	
			when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(first).thenReturn(second);
	
			long time = System.currentTimeMillis();
			
			// first jwks
			assertEquals(wrapper.get(aSelector, context), first.getKeys());
			verify(delegate, only()).getJWKSet(eq(false), anyLong(), anySecurityContext());
	
			ScheduledFuture<?> eagerJwkListCacheItem = provider.getScheduledRefreshFuture();
			assertNotNull(eagerJwkListCacheItem);
			
			long left = eagerJwkListCacheItem.getDelay(TimeUnit.MILLISECONDS);
			
			long skew = System.currentTimeMillis() - time;
	
			assertTrue(left <= timeToLive - refreshTimeout - preemptiveRefresh);
			assertTrue(left >= timeToLive - refreshTimeout - preemptiveRefresh - skew - 1);
	
			// sleep and check that keys were actually updated
			Thread.sleep(left + Math.min(25, 4 * skew));
			
			provider.getExecutorService().awaitTermination(Math.min(25, 4 * skew), TimeUnit.MILLISECONDS);
			verify(delegate, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
			
			// no new update necessary
			assertEquals(wrapper.get(bSelector, context), second.getKeys());
			verify(delegate, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
		} finally {
			wrapper.close();
		}
	}
}
