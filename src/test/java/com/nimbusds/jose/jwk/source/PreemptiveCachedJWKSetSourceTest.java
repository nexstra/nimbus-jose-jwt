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

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.only;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class PreemptiveCachedJWKSetSourceTest extends AbstractDelegateSourceTest {

	private Runnable lockRunnable = new Runnable() {
		@Override
		public void run() {
			if (!source.getLazyLock().tryLock()) {
				throw new RuntimeException();
			}
		}
	};

	private Runnable unlockRunnable = new Runnable() {
		@Override
		public void run() {
			source.getLazyLock().unlock();
		}
	};

	private static final String KID = "NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg";
	protected static final JWKSelector KID_SELECTOR = new JWKSelector(new JWKMatcher.Builder().keyID(KID).build());

	private PreemptiveCachedJWKSetSource<SecurityContext> source;

	private UrlJWKSource<SecurityContext> wrapper;

	@Before
	public void setUp() throws Exception {
		super.setUp();
		source = new PreemptiveCachedJWKSetSource<>(delegate, 3600 * 1000 * 10, 15 * 1000, 10 * 1000, false);

		wrapper = new UrlJWKSource<>(source);
	}

	@Test
	public void testShouldUseFallbackWhenNotCached() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks);
		assertEquals(source.getJWKSet(System.currentTimeMillis(), false, context), jwks);
	}

	@Test
	public void testShouldUseCachedValue() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks).thenThrow(new JWKSetUnavailableException("TEST!", null));
		source.getJWKSet(System.currentTimeMillis(), false, context);
		assertEquals(source.getJWKSet(System.currentTimeMillis(), false, context), jwks);
		verify(delegate, only()).getJWKSet(anyLong(), eq(false), anySecurityContext());
	}

	@Test
	public void testShouldUseFallbackWhenExpiredCache() throws Exception {
		JWKSet first = new JWKSet(jwk);
		JWKSet second = new JWKSet(Arrays.asList(jwk, jwk));

		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		assertEquals(source.getJWKSet(System.currentTimeMillis(), false, context), first);
		verify(delegate, only()).getJWKSet(anyLong(), eq(false), anySecurityContext());

		// second
		assertEquals(source.getJWKSet(source.getExpires(System.currentTimeMillis() + 1), false, context), second);
		verify(delegate, times(2)).getJWKSet(anyLong(), eq(false), anySecurityContext());
	}

	@Test
	public void testShouldNotReturnExpiredValueWhenExpiredCacheAndRefreshFails() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks).thenThrow(new KeySourceException("TEST!", null));
		assertEquals(source.getJWKSet(System.currentTimeMillis(), false, context), jwks);

		try {
			source.getJWKSet(source.getExpires(System.currentTimeMillis() + 1), false, context);
			fail();
		} catch(KeySourceException e) {
			// pass
		}
	}

	@Test
	public void testShouldGetBaseProvider() throws Exception {
		assertThat(source.getSource(), equalTo(delegate));
	}

	@Test
	public void testShouldUseCachedValueForKnownKey() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks).thenThrow(new KeySourceException("TEST!", null));
		assertEquals(wrapper.get(KID_SELECTOR, context), Arrays.asList(jwk));
		verify(delegate, only()).getJWKSet(anyLong(), eq(false), anySecurityContext());
	}

	@Test
	public void testShouldRefreshCacheForUncachedKnownKey() throws Exception {
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(Arrays.asList(b));

		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		assertEquals(wrapper.get(aSelector, context), first.getKeys());
		verify(delegate, only()).getJWKSet(anyLong(), eq(false), anySecurityContext());

		Thread.sleep(1);
		
		// second
		assertEquals(wrapper.get(bSelector, context), second.getKeys());
		verify(delegate, times(2)).getJWKSet(anyLong(), eq(false), anySecurityContext());
	}

	@Test
	public void testShouldRefreshCacheAndReturnEmptyForUnknownKey() throws Exception {
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(Arrays.asList(b));

		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first
		assertEquals(wrapper.get(aSelector, context), Arrays.asList(a));
		verify(delegate, only()).getJWKSet(anyLong(), eq(false), anySecurityContext());

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
		JWKSet second = new JWKSet(Arrays.asList(b));

		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first jwks
		List<JWK> longBeforeExpiryKeys = wrapper.get(aSelector, context);
		assertFalse(longBeforeExpiryKeys.isEmpty());
		assertEquals(longBeforeExpiryKeys, first.getKeys());
		verify(delegate, only()).getJWKSet(anyLong(), eq(false), anySecurityContext());

		long justBeforeExpiry = source.getExpires(System.currentTimeMillis()) - TimeUnit.SECONDS.toMillis(5);
		verify(delegate, only()).getJWKSet(anyLong(), eq(false), anySecurityContext());

		JWKSet justBeforeExpiryKeys = source.getJWKSet(justBeforeExpiry, false, context);
		assertFalse(justBeforeExpiryKeys.isEmpty());
		assertEquals(justBeforeExpiryKeys.getKeys(), first.getKeys()); // triggers a preemptive refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);
		verify(delegate, times(2)).getJWKSet(anyLong(), eq(false), anySecurityContext());

		// second jwks
		assertEquals(wrapper.get(bSelector, context), second.getKeys()); // should already be in cache
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(delegate, times(2)).getJWKSet(anyLong(), eq(false), anySecurityContext());
	}

	@Test
	public void testShouldNotPreemptivelyRefreshCacheIfRefreshAlreadyInProgress() throws Exception {
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(Arrays.asList(b));

		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(first).thenReturn(second);

		// first jwks
		assertEquals(wrapper.get(aSelector, context), first.getKeys());
		verify(delegate, only()).getJWKSet(anyLong(), eq(false), anySecurityContext());

		AbstractCachedJWKSetSource.JWKSetCacheItem cache = source.getCache(System.currentTimeMillis());

		long justBeforeExpiry = source.getExpires(System.currentTimeMillis()) - TimeUnit.SECONDS.toMillis(5);

		assertEquals(source.getJWKSet(justBeforeExpiry, false, context), first); // triggers a preemptive refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		source.preemptiveRefresh(justBeforeExpiry, cache, false, context); // should not trigger a preemptive refresh attempt

		verify(delegate, times(2)).getJWKSet(anyLong(), eq(false), anySecurityContext());

		// second jwks
		assertEquals(wrapper.get(bSelector, null), second.getKeys()); // should already be in cache
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(delegate, times(2)).getJWKSet(anyLong(), eq(false), anySecurityContext());
	}

	@Test
	public void testShouldFirePreemptivelyRefreshCacheAgainIfPreviousPreemptivelyRefreshAttemptFailed() throws Exception {
		JWK a = mock(JWK.class);
		when(a.getKeyID()).thenReturn("a");
		JWK b = mock(JWK.class);
		when(b.getKeyID()).thenReturn("b");

		JWKSet first = new JWKSet(a);
		JWKSet second = new JWKSet(Arrays.asList(b));

		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(first).thenThrow(new JWKSetUnavailableException("TEST!")).thenReturn(second);

		// first jwks
		assertEquals(wrapper.get(aSelector, context), first.getKeys());
		verify(delegate, only()).getJWKSet(anyLong(), eq(false), anySecurityContext());

		long justBeforeExpiry = source.getExpires(System.currentTimeMillis()) - TimeUnit.SECONDS.toMillis(5);

		assertEquals(source.getJWKSet(justBeforeExpiry, false, context), first); // triggers a preemptive refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		assertEquals(source.getJWKSet(justBeforeExpiry, false, context), first); // triggers a another preemptive refresh attempt

		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

		verify(delegate, times(3)).getJWKSet(anyLong(), eq(false), anySecurityContext());

		// second jwks
		assertEquals(wrapper.get(bSelector, context), second.getKeys()); // should already be in cache
		source.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
		verify(delegate, times(3)).getJWKSet(anyLong(), eq(false), anySecurityContext());
	}

	@Test
	public void testShouldAccceptIfAnotherThreadPreemptivelyUpdatesCache() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks);

		source.getJWKSet(System.currentTimeMillis(), false, context);

		long justBeforeExpiry = source.getExpires(System.currentTimeMillis()) - TimeUnit.SECONDS.toMillis(5);

		ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(unlockRunnable);
		try {
			helper.begin();

			source.getJWKSet(justBeforeExpiry, false, context); // wants to update, but can't get lock

			verify(delegate, only()).getJWKSet(anyLong(), eq(false), anySecurityContext());
		} finally {
			helper.close();
		}
	}

	@Test
	public void testShouldSchedulePreemptivelyRefreshCacheForKeys() throws Exception {
		long timeToLive = 1000; 
		long refreshTimeout = 150;
		long preemptiveRefresh = 300;

		PreemptiveCachedJWKSetSource<SecurityContext> provider = new PreemptiveCachedJWKSetSource<>(delegate, timeToLive, refreshTimeout, preemptiveRefresh, true);
		UrlJWKSource<SecurityContext> wrapper = new UrlJWKSource<>(provider);

		try {
			JWK a = mock(JWK.class);
			when(a.getKeyID()).thenReturn("a");
			JWK b = mock(JWK.class);
			when(b.getKeyID()).thenReturn("b");
	
			JWKSet first = new JWKSet(a);
			JWKSet second = new JWKSet(Arrays.asList(b));
	
			when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(first).thenReturn(second);
	
			long time = System.currentTimeMillis();
			
			// first jwks
			assertEquals(wrapper.get(aSelector, context), first.getKeys());
			verify(delegate, only()).getJWKSet(anyLong(), eq(false), anySecurityContext());
	
			ScheduledFuture<?> eagerJwkListCacheItem = provider.getEagerScheduledFuture();
			assertNotNull(eagerJwkListCacheItem);
			
			long left = eagerJwkListCacheItem.getDelay(TimeUnit.MILLISECONDS);
			
			long skew = System.currentTimeMillis() - time;
	
			assertTrue(left <= timeToLive - refreshTimeout - preemptiveRefresh);
			assertTrue(left >= timeToLive - refreshTimeout - preemptiveRefresh - skew - 1);
	
			// sleep and check that keys were actually updated
			Thread.sleep(left + Math.min(25, 4 * skew));
			
			provider.getExecutorService().awaitTermination(Math.min(25, 4 * skew), TimeUnit.MILLISECONDS);
			verify(delegate, times(2)).getJWKSet(anyLong(), eq(false), anySecurityContext());
			
			// no new update necessary
			assertEquals(wrapper.get(bSelector, context), second.getKeys());
			verify(delegate, times(2)).getJWKSet(anyLong(), eq(false), anySecurityContext());
		} finally {
			wrapper.close();
		}
	}
}
