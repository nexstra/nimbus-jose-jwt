/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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


import java.util.Date;
import java.util.concurrent.TimeUnit;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.jwk.JWKSet;


/**
 * JSON Web Key (JWK) set cache implementation.
 *
 * @author Vladimir Dzhuvinov
 * @author Sarvesh Sharma
 * @version 2021-01-08
 * @deprecated see {@linkplain RemoteJWKSet}.
 */
@ThreadSafe
@Deprecated
public class DefaultJWKSetCache implements JWKSetCache {
	
	
	/**
	 * The default lifespan for cached JWK sets (15 minutes).
	 */
	public static final long DEFAULT_LIFESPAN_MINUTES = 15;


	/**
	 * The default refresh time for cached JWK sets (5 minutes).
	 */
	public static final long DEFAULT_REFRESH_TIME_MINUTES = 5;

	
	/**
	 * The lifespan of the cached JWK set, in {@link #timeUnit}s, negative
	 * means no expiration.
	 */
	private final long lifespan;


	/**
	 * The refresh time of the cached JWK set, in {@link #timeUnit}s,
	 * negative means no refresh time.
	 */
	private final long refreshTime;

	
	/**
	 * The time unit, may be {@code null} if no expiration / refresh time.
	 */
	private final TimeUnit timeUnit;
	
	
	/**
	 * The cached JWK set, {@code null} if none.
	 */
	private volatile JWKSetWithTimestamp jwkSetWithTimestamp;
	
	
	/**
	 * Creates a new JWK set, the default lifespan of the cached JWK set is
	 * set to 15 minutes, the refresh time to 5 minutes.
	 */
	public DefaultJWKSetCache() {
		
		this(DEFAULT_LIFESPAN_MINUTES, DEFAULT_REFRESH_TIME_MINUTES, TimeUnit.MINUTES);
	}
	
	
	/**
	 * Creates a new JWK set cache.
	 *
	 * @param lifespan    The lifespan of the cached JWK set before it
	 *                    expires, negative means no expiration.
	 * @param refreshTime The time after which the cached JWK set is marked
	 *                    for refresh, negative if not specified. Should be
	 *                    shorter or equal to the lifespan.
	 * @param timeUnit    The lifespan time unit, may be {@code null} if no
	 *                    expiration or refresh time.
	 */
	public DefaultJWKSetCache(final long lifespan, final long refreshTime, final TimeUnit timeUnit) {
		
		this.lifespan = lifespan;
		this.refreshTime = refreshTime;

		if ((lifespan > -1 || refreshTime > -1) && timeUnit == null) {
			throw new IllegalArgumentException("A time unit must be specified for non-negative lifespans or refresh times");
		}
		
		this.timeUnit = timeUnit;
	}
	
	
	@Override
	public void put(final JWKSet jwkSet) {
		
		final JWKSetWithTimestamp updatedJWKSetWithTs;
		if (jwkSet != null) {
			updatedJWKSetWithTs = new JWKSetWithTimestamp(jwkSet);
		} else {
			// clear cache
			updatedJWKSetWithTs = null;
		}
		
		jwkSetWithTimestamp = updatedJWKSetWithTs;
	}
	
	
	@Override
	public JWKSet get() {
		
		if (jwkSetWithTimestamp == null || isExpired()) {
			return null;
		}
		
		return jwkSetWithTimestamp.getJWKSet();
	}


	@Override
	public boolean requiresRefresh() {

		return jwkSetWithTimestamp != null &&
			refreshTime > -1 &&
			new Date().getTime() > jwkSetWithTimestamp.getDate().getTime() + TimeUnit.MILLISECONDS.convert(refreshTime, timeUnit);
	}

	
	/**
	 * Returns the cache put timestamp.
	 *
	 * @return The cache put timestamp, negative if not specified.
	 */
	public long getPutTimestamp() {
		
		return jwkSetWithTimestamp != null ? jwkSetWithTimestamp.getDate().getTime() : -1L;
	}
	
	
	/**
	 * Returns {@code true} if the cached JWK set is expired.
	 *
	 * @return {@code true} if expired.
	 */
	public boolean isExpired() {
	
		return jwkSetWithTimestamp != null &&
			lifespan > -1 &&
			new Date().getTime() > jwkSetWithTimestamp.getDate().getTime() + TimeUnit.MILLISECONDS.convert(lifespan, timeUnit);
	}
	
	
	/**
	 * Returns the configured lifespan of the cached JWK.
	 *
	 * @param timeUnit The time unit to use.
	 *
	 * @return The configured lifespan, negative means no expiration.
	 */
	public long getLifespan(final TimeUnit timeUnit) {
		
		if (lifespan < 0) {
			return lifespan;
		}

		return timeUnit.convert(lifespan, this.timeUnit);
	}


	/**
	 * Returns the configured refresh time of the cached JWK.
	 *
	 * @param timeUnit The time unit to use.
	 *
	 * @return The configured refresh time, negative means no expiration.
	 */
	public long getRefreshTime(final TimeUnit timeUnit) {

		if (refreshTime < 0) {
			return refreshTime;
		}

		return timeUnit.convert(refreshTime, this.timeUnit);
	}
}
