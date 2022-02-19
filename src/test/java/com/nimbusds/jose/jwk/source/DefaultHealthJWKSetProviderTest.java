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
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class DefaultHealthJWKSetProviderTest extends AbstractDelegateProviderTest {

	private DefaultHealthJWKSetProvider provider;
	private JWKSetProvider refreshProvider = mock(JWKSetProvider.class);

	@Before
	public void setUp() throws Exception {
		super.setUp();
		provider = new DefaultHealthJWKSetProvider(delegate);
		provider.setRefreshProvider(refreshProvider);
		
		when(refreshProvider.getJWKSet(anyLong(), eq(false))).thenReturn(jwks);
		when(refreshProvider.getJWKSet(anyLong(), eq(true))).thenReturn(jwks);
	}

	@Test
	public void testShouldReturnUnknownHealthIfNoPreviousStatusAndRefreshingIsNotAllowed() throws Exception {
		JWKSetHealth health = provider.getHealth(false);
		assertNull(health);

		// expected behavior: the health provider did not attempt to refresh status.
		Mockito.verify(refreshProvider, times(0)).getJWKSet(anyLong(), eq(false));
		Mockito.verify(delegate, times(0)).getJWKSet(anyLong(), eq(false));
	}

	@Test
	public void testShouldReturnGoodHealth() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false))).thenReturn(jwks);

		// attempt to get access-token
		provider.getJWKSet(System.currentTimeMillis(), false);

		JWKSetHealth health1 = provider.getHealth(true);
		assertTrue(health1.isSuccess());

		JWKSetHealth health2 = provider.getHealth(false);
		assertSame(health1, health2);

		// expected behavior: the health provider did not attempt to refresh
		// a good health status.
		Mockito.verify(delegate, times(1)).getJWKSet(anyLong(), eq(false));
		Mockito.verify(refreshProvider, times(0)).getJWKSet(anyLong(), eq(false));
	}

	@Test
	public void testShouldReturnGoodHealthIfJwksCouldBeRefreshedAfterBadStatus() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false))).thenThrow(new KeySourceException("test"));

		// attempt to get jwks
		try {
			JWKSet jwkSet = provider.getJWKSet(System.currentTimeMillis(), false);
			assertTrue(jwkSet.isEmpty());
			fail();
		} catch (KeySourceException e) {
			// pass
		}

		JWKSetHealth health = provider.getHealth(true);
		assertTrue(health.isSuccess());

		// expected behavior: the health provider refreshed
		// a bad health status.
		Mockito.verify(delegate, times(1)).getJWKSet(anyLong(), eq(false));
		Mockito.verify(refreshProvider, times(1)).getJWKSet(anyLong(), eq(false));
	}

	@Test
	public void testShouldReturnBadHealthIfJwksCouldNotBeRefreshedAfterBadStatus() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false))).thenThrow(new KeySourceException("test"));
		when(refreshProvider.getJWKSet(anyLong(), eq(false))).thenThrow(new KeySourceException("test"));

		// attempt to get jwks
		try {
			provider.getJWKSet(System.currentTimeMillis(), false);
			fail();
		} catch (KeySourceException e) {
			// pass
		}

		JWKSetHealth health = provider.getHealth(true);
		assertFalse(health.isSuccess());

		// expected behavior: the health provider refreshed
		// a bad health status.
		Mockito.verify(delegate, times(1)).getJWKSet(anyLong(), eq(false));
		Mockito.verify(refreshProvider, times(1)).getJWKSet(anyLong(), eq(false));
	}

	@Test
	public void testShouldRecoverFromBadHealth() throws Exception {
		when(delegate.getJWKSet(anyLong(), eq(false))).thenThrow(new KeySourceException("test")) // fail
				.thenReturn(jwks); // recover

		// attempt to get access-token
		try {
			provider.getJWKSet(System.currentTimeMillis(), false);
			fail();
		} catch (KeySourceException e) {
			// pass
		}
		
		provider.getJWKSet(System.currentTimeMillis(), false);

		JWKSetHealth health1 = provider.getHealth(false);
		assertTrue(health1.isSuccess());
		
		JWKSetHealth health2 = provider.getHealth(true);
		assertSame(health1, health2);
		
		Mockito.verify(delegate, times(2)).getJWKSet(anyLong(), eq(false));
		Mockito.verify(refreshProvider, times(0)).getJWKSet(anyLong(), eq(false));
	}	

}
