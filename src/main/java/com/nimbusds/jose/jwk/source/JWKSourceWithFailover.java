/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2022, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.jwk.source;


import java.io.Closeable;
import java.util.List;
import java.util.Objects;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthStatus;
import com.nimbusds.jose.util.health.HealthStatusReporting;


/**
 * JWK source with optional failover.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-09
 */
@ThreadSafe
public class JWKSourceWithFailover<C extends SecurityContext> implements JWKSource<C>, HealthStatusReporting<C>, Closeable {
	
	private final JWKSource<C> jwkSource;
	private final JWKSource<C> failoverJWKSource;

	private final HealthStatusReporting<C> jwkSourceHealthSource;
	private final HealthStatusReporting<C> failoverJWKSourceHealthSource;

	
	/**
	 * Creates a new JWK source with optional failover.
	 *
	 * @param jwkSource         The primary JWK source. Must not be
	 *                          {@code null}.
	 * @param failoverJWKSource Optional failover JWK source if retrieval
	 *                          from the primary JWK source fails,
	 *                          {@code null} if no failover.
	 */
	public JWKSourceWithFailover(final JWKSource<C> jwkSource, final JWKSource<C> failoverJWKSource) {
		Objects.requireNonNull(jwkSource, "The primary JWK source must not be null");
		this.jwkSource = jwkSource;
		this.failoverJWKSource = failoverJWKSource;

		this.jwkSourceHealthSource = toHealthStatusReporting(jwkSource);
		this.failoverJWKSourceHealthSource = toHealthStatusReporting(failoverJWKSource);
	}

	@SuppressWarnings("unchecked")
	private HealthStatusReporting<C> toHealthStatusReporting(final JWKSource<C> source) {
		if (source instanceof HealthStatusReporting) {
			return (HealthStatusReporting<C>) source;
		}
		return null;
	}

	
	/**
	 * Fails over to the configured JWK source.
	 */
	private List<JWK> failover(final Exception exception, final JWKSelector jwkSelector, final C context)
		throws KeySourceException {

		try {
			return failoverJWKSource.get(jwkSelector, context);
		} catch (KeySourceException kse) {
			throw new KeySourceException(
				exception.getMessage() + "; Failover JWK source retrieval failed with: " + kse.getMessage(), kse
			);
		}
	}
	

	@Override
	public List<JWK> get(final JWKSelector jwkSelector, final C context)
		throws KeySourceException {
		
		try {
			return jwkSource.get(jwkSelector, context);
		} catch (Exception e) {
			return failover(e, jwkSelector, context);
		}
	}

	
	@Override
	public void close() {
		if (jwkSource instanceof Closeable) {
			IOUtils.closeSilently((Closeable)jwkSource);
		}
		if (failoverJWKSource instanceof Closeable) {
			IOUtils.closeSilently((Closeable)failoverJWKSource);
		}
	}

	
	@Override
	public HealthReport reportHealthStatus(final boolean refresh, final C context) {
		HealthReport health = null;
		if (jwkSourceHealthSource != null) {
			health = jwkSourceHealthSource.reportHealthStatus(refresh, context);
		}
		if (health == null || HealthStatus.NOT_HEALTHY.equals(health.getHealthStatus())) {
			if (failoverJWKSourceHealthSource != null) {
				health = failoverJWKSourceHealthSource.reportHealthStatus(refresh, context);
			}
		}
		if (health == null) {
			health = new HealthReport(HealthStatus.UNKNOWN);
		}
		return health;
	}
}
