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
import com.nimbusds.jose.proc.SecurityContext;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OutageCachedJWKSetSourceTest extends AbstractDelegateSourceTest {

	private OutageCachedJWKSetSource<SecurityContext> provider;

	@Before
	public void setUp() throws Exception {
		super.setUp();
		provider = new OutageCachedJWKSetSource<>(delegate, 10 * 3600 * 1000);
	}

	@Test
	public void testShouldUseDelegate() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false, context), jwks);
	}

	@Test
	public void testShouldUseDelegateWhenCached() throws Exception {
		JWKSet last = new JWKSet(Arrays.asList(jwk, jwk));

		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks).thenReturn(last);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false, context), jwks);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false, context), last);
	}

	@Test
	public void testShouldUseCacheWhenDelegateSigningKeyUnavailable() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks).thenThrow(new JWKSetUnavailableException("TEST", null));
		provider.getJWKSet(System.currentTimeMillis(), false, context);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false, context), jwks);
		verify(delegate, times(2)).getJWKSet(anyLong(), eq(false), anySecurityContext());
	}

	@Test
	public void testShouldNotUseExpiredCacheWhenDelegateSigningKeyUnavailable() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks).thenThrow(new JWKSetUnavailableException("TEST", null));
		provider.getJWKSet(System.currentTimeMillis(), false, context);

		try {
			provider.getJWKSet(provider.getExpires(System.currentTimeMillis() + 1), false, context);
			fail();
		} catch(JWKSetUnavailableException e) {
			// pass
		}
	}

	@Test
	public void testShouldGetBaseProvider() {
		assertEquals(provider.getSource(), delegate);
	}
}
