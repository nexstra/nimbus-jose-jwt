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
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.log.JWKSetSourceWithHealthStatusReportingLogger;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthStatus;


public class JWKSetSourceWithHealthStatusReportingTest extends AbstractDelegateSourceTest {

	private JWKSetSourceWithHealthStatusReporting<SecurityContext> source;
	private JWKSetSource<SecurityContext> refreshProvider = mock(JWKSetSource.class);

	private JWKSetSourceWithHealthStatusReporting.Listener<SecurityContext> listener = new JWKSetSourceWithHealthStatusReportingLogger<>(Level.INFO);
	
	@Before
	public void setUp() throws Exception {
		super.setUp();
		source = new JWKSetSourceWithHealthStatusReporting<>(delegate, listener);
		source.setTopLevelSource(refreshProvider);
		
		when(refreshProvider.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);
		when(refreshProvider.getJWKSet(eq(true), anyLong(), anySecurityContext())).thenReturn(jwkSet);
	}

	@Test
	public void testShouldReturnUnknownHealthIfNoPreviousStatusAndRefreshingIsNotAllowed() throws Exception {
		assertEquals(HealthStatus.UNKNOWN, source.reportHealthStatus(false, context).getHealthStatus());

		// expected behavior: the health provider did not attempt to refresh status.
		Mockito.verify(refreshProvider, times(0)).getJWKSet(eq(false), anyLong(), anySecurityContext());
		Mockito.verify(delegate, times(0)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldReturnGoodHealth() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenReturn(jwkSet);

		// attempt to get JWK set
		source.getJWKSet(false, System.currentTimeMillis(), context);

		HealthReport health1 = source.reportHealthStatus(true, context);
		assertEquals(HealthStatus.HEALTHY, health1.getHealthStatus());

		HealthReport health2 = source.reportHealthStatus(false, context);
		assertSame(health1, health2);

		// expected behavior: the health provider did not attempt to refresh
		// a good health status.
		Mockito.verify(delegate, times(1)).getJWKSet(eq(false), anyLong(), anySecurityContext());
		Mockito.verify(refreshProvider, times(0)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldReturnGoodHealthIfJwksCouldBeRefreshedAfterBadStatus() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenThrow(new KeySourceException("test"));

		// attempt to get JWK set
		try {
			JWKSet jwkSet = source.getJWKSet(false, System.currentTimeMillis(), context);
			assertTrue(jwkSet.isEmpty());
			fail();
		} catch (KeySourceException e) {
			assertEquals("test", e.getMessage());
		}

		HealthReport health = source.reportHealthStatus(true, context);
		assertEquals(HealthStatus.HEALTHY, health.getHealthStatus());

		// expected behavior: the health provider refreshed
		// a bad health status.
		Mockito.verify(delegate, times(1)).getJWKSet(eq(false), anyLong(), anySecurityContext());
		Mockito.verify(refreshProvider, times(1)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldReturnBadHealthIfJwksCouldNotBeRefreshedAfterBadStatus() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenThrow(new KeySourceException("test"));
		when(refreshProvider.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenThrow(new KeySourceException("test"));

		// attempt to get jwks
		try {
			source.getJWKSet(false, System.currentTimeMillis(), context);
			fail();
		} catch (KeySourceException e) {
			assertEquals("test", e.getMessage());
		}

		HealthReport health = source.reportHealthStatus(true, context);
		assertEquals(HealthStatus.NOT_HEALTHY, health.getHealthStatus());

		// expected behavior: the health provider refreshed
		// a bad health status.
		Mockito.verify(delegate, times(1)).getJWKSet(eq(false), anyLong(), anySecurityContext());
		Mockito.verify(refreshProvider, times(1)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}

	@Test
	public void testShouldRecoverFromBadHealth() throws Exception {
		when(delegate.getJWKSet(eq(false), anyLong(), anySecurityContext())).thenThrow(new KeySourceException("test")) // fail
				.thenReturn(jwkSet); // recover

		// attempt to get JWK set
		try {
			source.getJWKSet(false, System.currentTimeMillis(), context);
			fail();
		} catch (KeySourceException e) {
			assertEquals("test", e.getMessage());
		}
		
		source.getJWKSet(false, System.currentTimeMillis(), context);

		HealthReport health1 = source.reportHealthStatus(false, context);
		assertEquals(HealthStatus.HEALTHY, health1.getHealthStatus());
		
		HealthReport health2 = source.reportHealthStatus(true, context);
		assertSame(health1, health2);
		
		Mockito.verify(delegate, times(2)).getJWKSet(eq(false), anyLong(), anySecurityContext());
		Mockito.verify(refreshProvider, times(0)).getJWKSet(eq(false), anyLong(), anySecurityContext());
	}
}
