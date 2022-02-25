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

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RateLimitedJWKSetSourceTest extends AbstractDelegateSourceTest {

	private RateLimitedJWKSetSource provider;

	private int duration = 30 * 1000;
	
	@Before
	public void setUp() throws Exception {
		super.setUp();
		provider = new RateLimitedJWKSetSource(delegate, duration);
	}

	@Test
	public void testShouldFailToGetWhenBucketIsEmpty() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false))).thenReturn(jwks);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false), jwks);
		assertEquals(provider.getJWKSet(System.currentTimeMillis() + 1, false), jwks);
		try {
			provider.getJWKSet(System.currentTimeMillis(), false);
			fail();
		} catch(RateLimitReachedException e) {
			// pass
		}
	}
	
	@Test
	public void testRefillBucket() throws Exception {
		long time = System.currentTimeMillis();
		
		when(delegate.getJWKSet(anyLong(), eq(false))).thenReturn(jwks);
		assertEquals(provider.getJWKSet(time, false), jwks);
		assertEquals(provider.getJWKSet(time + 1, false), jwks);
		try {
			provider.getJWKSet(time + 2, false);
			fail();
		} catch(RateLimitReachedException e) {
			// pass
		}
		
		assertEquals(provider.getJWKSet(time + duration, false), jwks);
		
	}

	@Test
	public void testShouldGetWhenBucketHasTokensAvailable() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false))).thenReturn(jwks);

		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false), jwks);
		verify(delegate).getJWKSet(anyLong(), eq(false));
	}

}
