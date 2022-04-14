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

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.cache.CachedObject;


/**
 * Abstract caching {@linkplain JWKSetSource}.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-09
 */
@ThreadSafe
abstract class AbstractCachingJWKSetSource<C extends SecurityContext> extends JWKSetSourceWrapper<C> {

	private volatile CachedObject<JWKSet> cachedJWKSet;
	private final long timeToLive; // milliseconds
	
	
	/**
	 * Creates a new abstract caching JWK set source.
	 *
	 * @param source     The JWK set source to decorate. Must not be
	 *                   {@code null}.
	 * @param timeToLive The time to live of the cached JWK set, in
	 *                   milliseconds.
	 */
	AbstractCachingJWKSetSource(final JWKSetSource<C> source, final long timeToLive) {
		super(source);
		this.timeToLive = timeToLive;
	}
	
	
	/**
	 * Returns the cached JWK set.
	 *
	 * @return The cached JWK set, {@code null} if none.
	 */
	CachedObject<JWKSet> getCachedJWKSet() {
		return cachedJWKSet;
	}
	
	
	/**
	 * Sets the cached JWK set.
	 *
	 * @param cachedJWKSet The cached JWK set, {@code null} if none.
	 */
	void setCachedJWKSet(final CachedObject<JWKSet> cachedJWKSet) {
		this.cachedJWKSet = cachedJWKSet;
	}
	
	
	/**
	 * Returns the cached JWK set if valid (not expired).
	 *
	 * @param currentTime The current time, in milliseconds since the Unix
	 *                    epoch.
	 *
	 * @return The cached JWK set, {@code null} if expired or none.
	 */
	CachedObject<JWKSet> getCachedJWKSetIfValid(final long currentTime) {
		CachedObject<JWKSet> threadSafeCache = getCachedJWKSet(); // defensive copy
		if (threadSafeCache != null && threadSafeCache.isValid(currentTime)) {
			return threadSafeCache;
		}
		return null;
	}

	
	/**
	 * Returns the time to live of the cached JWK set.
	 *
	 * @return The time to live, in milliseconds.
	 */
	public long getTimeToLive() {
		return timeToLive;
	}
	
	
	/**
	 * Caches the specified JWK set.
	 *
	 * @param jwkSet    The JWK set. Must not be {@code null}.
	 * @param fetchTime The fetch time, in milliseconds since the Unix
	 *                  epoch.
	 *
	 * @return Reference to the cached JWK set.
	 */
	CachedObject<JWKSet> cacheJWKSet(final JWKSet jwkSet, final long fetchTime) {
		
		// Set a new timestamp, so that threads which did a
		// read-then-force-refresh can identify that the keys were in
		// fact updated if multiple threads wanted to force refresh at the same time
		long currentTime = currentTimeMillis();
		CachedObject<JWKSet> cachedJWKSet = new CachedObject<>(jwkSet, currentTime, CachedObject.computeExpirationTime(fetchTime, getTimeToLive()));
		setCachedJWKSet(cachedJWKSet);
		return cachedJWKSet;
	}
	
	
	long currentTimeMillis() {
		return System.currentTimeMillis();
	}
}
