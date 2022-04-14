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


import java.util.Objects;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthStatus;


/**
 * Decorates a {@linkplain JWKSetSource} with health status reporting at two
 * check (wrap) points. TODO describe them
 *
 * <p>TODO edit below to improve clarify which invocation - getJWKSet or
 * reportHealthStatus?
 *
 * <p>Reports good health:
 * <ul>
 *     <li>a previous invocation was successful, or
 *     <li>a previous invocation failed, but a new invocation (from the top
 *         level) is successful.
 * </ul>
 *
 * <p>Reports bad health:
 * <ul>
 *     <li>a previous invocation failed, and a new invocation (from the top
 *         level) fails as well.
 * </ul>
 *
 * <p>Calls to this health reporter do not trigger retrieval from the wrapped
 * JWK set source if the last call to it was successful.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-14
 */
@ThreadSafe
public class JWKSetSourceWithHealthStatusReporting<C extends SecurityContext> extends JWKSetSourceWrapper<C> {
	
	
	public interface Listener<C extends SecurityContext> extends JWKSetSourceListener<C> {
		
		void onHealthRefreshException(Exception e, C context);
	}
	
	
	/** The top-level source. */
	private JWKSetSource<C> topLevelSource;
	
	/** The status of the last JWK set retrieval. */
	private volatile HealthReport statusOfLastJWKSetRetrieval;
	
	/**
	 * The status of the last health check, initiated from the top-level
	 * JWK set source.
	 */
	private volatile HealthReport statusOfLastHealthCheck;
	
	private final Listener<C> listener;
	
	
	/**
	 * TODO
	 * Construction is completed after setting the
	 * {@linkplain #setTopLevelSource top-level source}.
	 *
	 * @param source   The JWK set source to wrap. Must not be {@code null}.
	 * @param listener The listener, {@code null} if not specified.
	 */
	public JWKSetSourceWithHealthStatusReporting(final JWKSetSource<C> source, final Listener<C> listener) {
		super(source);
		this.listener = listener;
	}
	
	
	/**
	 * Sets the top-level {@linkplain JWKSetSource} to complete the
	 * construction.
	 *
	 * @param topLevelSource The top-level source. Must not be
	 *                       {@code null}.
	 */
	public void setTopLevelSource(final JWKSetSource<C> topLevelSource) {
		Objects.requireNonNull(topLevelSource);
		this.topLevelSource = topLevelSource;
	}
	
	
	private void ensureTopLevelSource() {
		if (topLevelSource == null) {
			throw new IllegalStateException("The top-level source must be set");
		}
	}
	
	
	@Override
	public JWKSet getJWKSet(final boolean forceReload, final long currentTime, final C context) throws KeySourceException {
		
		ensureTopLevelSource();
		
		JWKSet jwkSet = null;
		try {
			jwkSet = getSource().getJWKSet(forceReload, currentTime, context);
		} finally {
			this.statusOfLastJWKSetRetrieval = new HealthReport(jwkSet != null ? HealthStatus.HEALTHY : HealthStatus.NOT_HEALTHY, currentTime);
		}

		return jwkSet;
	}
	
	
	@Override
	public HealthReport reportHealthStatus(final boolean refresh, final C context) {
		
		ensureTopLevelSource();
		
		return reportHealthStatus(System.currentTimeMillis(), refresh, context);
	}
	
	
	private HealthReport reportHealthStatus(final long currentTime, final boolean refresh, final C context) {
		
		if (! refresh) {
			HealthReport threadSafeStatus = this.statusOfLastHealthCheck; // defensive copy
			if (threadSafeStatus != null) {
				return threadSafeStatus;
			}
			if (statusOfLastJWKSetRetrieval != null) {
				return statusOfLastJWKSetRetrieval;
			}
			return new HealthReport(HealthStatus.UNKNOWN); // occurs if JWKs never retrieved
		}
		// assuming a successful call to the underlying source always results
		// in a healthy top-level source.
		//
		// If the last call to the underlying source is not successful
		// get the JWKs from the top level source (without forcing a refresh)
		// so that the cache is refreshed if necessary, so an unhealthy status
		// can turn to a healthy status just by checking the health
		HealthReport threadSafeStatus = this.statusOfLastJWKSetRetrieval; // defensive copy
		if (threadSafeStatus == null || HealthStatus.NOT_HEALTHY.equals(threadSafeStatus.getHealthStatus())) {
			// refresh the top-level status
			JWKSet jwkSet = null;
			try {
				jwkSet = topLevelSource.getJWKSet(false, currentTime, context);
			} catch (Exception e) {
				// ignore
				if (listener != null) {
					listener.onHealthRefreshException(e, context);
				}
			} finally {
				// as long as the JWK set was returned, health is good
				threadSafeStatus = new HealthReport(jwkSet != null ? HealthStatus.HEALTHY : HealthStatus.NOT_HEALTHY);
			}
		} else {
			// promote the latest JWKs retrieval status to top-level
		}
		this.statusOfLastHealthCheck = threadSafeStatus;
		return threadSafeStatus;
	}
}
