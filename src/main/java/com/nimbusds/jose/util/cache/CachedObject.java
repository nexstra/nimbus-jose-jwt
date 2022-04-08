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

package com.nimbusds.jose.util.cache;


import net.jcip.annotations.Immutable;


/**
 * Cached object.
 *
 * @param <V> The object type.
 *
 * @version 2022-04-08
 */
@Immutable
public final class CachedObject<V> {
	
	
	private final V object;
	private final long timestamp;
	private final long expirationTime;
	
	
	/**
	 * Computes expiration time.
	 *
	 * @param currentTime The current time, in milliseconds since the Unix
	 *                    epoch.
	 * @param timeToLive  The time to live, in milliseconds.
	 *
	 * @return The expiration time, in milliseconds since the Unix epoch.
	 */
	public static long computeExpirationTime(final long currentTime, final long timeToLive) {
		return currentTime + timeToLive;
	}
	
	
	/**
	 * Creates a new cached object.
	 *
	 * @param object         The cached object. Must not be {@code null}.
	 * @param timestamp      The caching timestamp, in milliseconds since
	 *                       the Unix epoch.
	 * @param expirationTime The expiration time, in milliseconds since the
	 *                       Unix epoch.
	 */
	public CachedObject(final V object, final long timestamp, final long expirationTime) {
		if (object == null) {
			throw new IllegalArgumentException("The object must not be null");
		}
		this.object = object;
		this.timestamp = timestamp;
		this.expirationTime = expirationTime;
	}
	
	
	/**
	 * Returns the cached object.
	 *
	 * @return The cached object.
	 */
	public V get() {
		return object;
	}
	
	
	/**
	 * Returns the caching timestamp.
	 *
	 * @return The caching timestamp, in milliseconds since the Unix epoch.
	 */
	public long getTimestamp() {
		return timestamp;
	}
	
	
	/**
	 * Returns the expiration time.
	 *
	 * @return The expiration time, in milliseconds since the Unix epoch.
	 */
	public long getExpirationTime() {
		return expirationTime;
	}
	
	
	/**
	 * Returns {@code true} if the cached object is valid.
	 *
	 * @param currentTime The current time, in milliseconds since the Unix
	 *                    epoch.
	 *
	 * @return {@code true} if the cached object is valid, else
	 *         {@code false}.
	 */
	public boolean isValid(final long currentTime) {
		return currentTime < expirationTime;
	}
	
	
	/**
	 * Returns {@code true} if the cached object expired.
	 *
	 * @param currentTime The current time, in milliseconds since the Unix
	 *                    epoch.
	 *
	 * @return {@code true} if the cached object expired, else
	 *         {@code false}.
	 */
	public boolean isExpired(final long currentTime) {
		return ! isValid(currentTime);
	}
}
