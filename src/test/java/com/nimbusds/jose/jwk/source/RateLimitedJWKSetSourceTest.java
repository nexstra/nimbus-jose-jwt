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


import java.util.logging.Level;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.jwk.source.log.RateLimitedJWKSetSourceLogger;
import com.nimbusds.jose.proc.SecurityContext;

public class RateLimitedJWKSetSourceTest extends AbstractDelegateSourceTest {

	private RateLimitedJWKSetSource<SecurityContext> source;

	private final int minTimeInterval = 30_000;
	
	private RateLimitedJWKSetSource.Listener<SecurityContext> listener = new RateLimitedJWKSetSourceLogger<SecurityContext>(Level.INFO);
	
	@Before
	public void setUp() throws Exception {
		super.setUp();
		source = new RateLimitedJWKSetSource<>(delegate, minTimeInterval, listener);
	}

	@Test
	public void testShouldFailToGetWhenBucketIsEmpty() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);
		assertEquals(source.getJWKSet(false, System.currentTimeMillis() + 1, context), jwkSet);
		try {
			source.getJWKSet(false, System.currentTimeMillis(), context);
			fail();
		} catch(RateLimitReachedException e) {
			// pass
			assertNull(e.getMessage());
		}
	}

	@Test
	public void testShouldFailToGetWhenBucketIsEmpty_forceUpdate() throws Exception {
		when(delegate.getJWKSet(eq(true), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(source.getJWKSet(true, System.currentTimeMillis(), context), jwkSet);
		assertEquals(source.getJWKSet(true, System.currentTimeMillis() + 1, context), jwkSet);
		try {
			source.getJWKSet(true, System.currentTimeMillis(), context);
			fail();
		} catch(RateLimitReachedException e) {
			// pass
			assertNull(e.getMessage());
		}
	}
	
	@Test
	public void testRefillBucket() throws Exception {
		
		long time = System.currentTimeMillis();
		
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		assertEquals(source.getJWKSet(false, time, context), jwkSet);
		assertEquals(source.getJWKSet(false, time + 1, context), jwkSet);
		try {
			source.getJWKSet(false, time + 2, context);
			fail();
		} catch(RateLimitReachedException e) {
			// pass
			assertNull(e.getMessage());
		}
		
		assertEquals(source.getJWKSet(false, time + minTimeInterval, context), jwkSet);
	}

	@Test
	public void testShouldGetWhenBucketHasTokensAvailable() throws Exception {
		
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		
		assertEquals(source.getJWKSet(false, System.currentTimeMillis(), context), jwkSet);
		verify(delegate).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}
}
