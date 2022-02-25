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

import com.nimbusds.jose.proc.SecurityContext;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RetryingJWKSetSourceTest extends AbstractDelegateSourceTest {

	private RetryingJWKSetSource<SecurityContext> provider;

	@Before
	public void setUp() throws Exception {
		super.setUp();
		provider = new RetryingJWKSetSource<>(delegate);
	}

	@Test
	public void testShouldReturnListOnSuccess() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenReturn(jwks);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false, context), jwks);
		verify(delegate, times(1)).getJWKSet(anyLong(), eq(false), anySecurityContext());
	}

	@Test
	public void testShouldRetryWhenUnavailable() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenThrow(new JWKSetUnavailableException("TEST!", null)).thenReturn(jwks);
		assertEquals(provider.getJWKSet(System.currentTimeMillis(), false, context), jwks);
		verify(delegate, times(2)).getJWKSet(anyLong(), eq(false), anySecurityContext());
	}

	@Test
	public void testShouldNotRetryMoreThanOnce() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false), anySecurityContext())).thenThrow(new JWKSetUnavailableException("TEST!", null));

		try {
			provider.getJWKSet(System.currentTimeMillis(), false, context);
			fail();
		} catch(JWKSetUnavailableException e) {
			// pass
		} finally {
			verify(delegate, times(2)).getJWKSet(anyLong(), eq(false), anySecurityContext());
		}
	}

	public void testShouldGetBaseProvider() throws Exception {
		assertEquals(provider.getSource(), delegate);
	}
}
