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

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OutageCachedJWKSetProviderTest extends AbstractDelegateProviderTest {

	private OutageCachedJWKSetProvider provider;

	@Before
	public void setUp() throws Exception {
		super.setUp();
		provider = new OutageCachedJWKSetProvider(delegate, 10 * 3600 * 1000);
	}

	@Test
	public void testShouldUseDelegate() throws Exception {
		when(delegate.getJWKSet(false)).thenReturn(jwks);
		assertEquals(provider.getJWKSet(false), jwks);
	}

	@Test
	public void testShouldUseDelegateWhenCached() throws Exception {
		JWKSet last = new JWKSet(Arrays.asList(jwk, jwk));

		when(delegate.getJWKSet(false)).thenReturn(jwks).thenReturn(last);
		assertEquals(provider.getJWKSet(false), jwks);
		assertEquals(provider.getJWKSet(false), last);
	}

	@Test
	public void testShouldUseCacheWhenDelegateSigningKeyUnavailable() throws Exception {
		when(delegate.getJWKSet(false)).thenReturn(jwks).thenThrow(new JWKSetUnavailableException("TEST", null));
		provider.getJWKSet(false);
		assertEquals(provider.getJWKSet(false), jwks);
		verify(delegate, times(2)).getJWKSet(false);
	}

	@Test
	public void testShouldNotUseExpiredCacheWhenDelegateSigningKeyUnavailable() throws Exception {
		when(delegate.getJWKSet(false)).thenReturn(jwks).thenThrow(new JWKSetUnavailableException("TEST", null));
		provider.getJWKSet(false);

		try {
			provider.getJWKSet(provider.getExpires(System.currentTimeMillis() + 1), false);
			fail();
		} catch(JWKSetUnavailableException e) {
			// pass
		}
	}

	@Test
	public void testShouldGetBaseProvider() {
		assertEquals(provider.getProvider(), delegate);
	}
}
