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

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

/**
 * Caching {@linkplain JWKSetProvider}. Blocks when the cache is updated.
 */

public class DefaultCachedJWKSetProvider extends AbstractCachedJWKSetProvider {

	private static final Logger LOGGER = Logger.getLogger(DefaultCachedJWKSetProvider.class.getName());

	protected final ReentrantLock lock = new ReentrantLock();

	protected final long refreshTimeout;

	/**
	 * Construct new instance.
	 * 
	 * @param provider	   Jwk provider
	 * @param timeToLive	 cache hold time (in milliseconds)
	 * @param refreshTimeout cache refresh timeout unit
	 */

	public DefaultCachedJWKSetProvider(JWKSetProvider provider, long timeToLive, long refreshTimeout) {
		super(provider, timeToLive);

		this.refreshTimeout = refreshTimeout;
	}

	@Override
	public JWKSet getJWKSet(boolean forceUpdate) throws KeySourceException {
		return getJWKSet(System.currentTimeMillis(), forceUpdate);
	}

	protected JWKSet getJWKSet(long time, boolean forceUpdate) throws KeySourceException {
		JWKSetCacheItem cache = this.cache;
		if (forceUpdate || cache == null || !cache.isValid(time)) {
			cache = getJwksBlocking(time, cache);
		}

		return cache.getValue();
	}

	protected JWKSetCacheItem getJwksBlocking(long time, JWKSetCacheItem cache) throws KeySourceException {
		// Synchronize so that the first thread to acquire the lock
		// exclusively gets to call the underlying provider.
		// Other (later) threads must wait until the result is ready.
		//
		// If the first to get the lock fails within the waiting interval,
		// subsequent threads will attempt to update the cache themselves.
		//
		// This approach potentially blocks a number of threads,
		// but requesting the same data downstream is not better, so
		// this is a necessary evil.

		try {
			if(lock.tryLock()) {
				try {
					// see if anyone already refreshed the cache while we were
					// hold getting the lock
					if (cache == this.cache) {
						// Seems cache was not updated.
						// We hold the lock, so safe to update it now
						LOGGER.info("Perform JWK cache refresh..");

						JWKSetCacheItem result = loadJWKSetFromProvider(time);

						LOGGER.info("JWK cache refreshed (with " + lock.getQueueLength() + " waiting), now have " + result.getValue().size() + " JWKs");

						cache = result;
					} else {
						// load updated value
						cache = this.cache;
						
						LOGGER.info("JWK cache was previously refreshed");
					}
				} finally {
					lock.unlock();
				}
			} else {
				LOGGER.info("Wait for up to " + refreshTimeout + "ms for the JWK cache to be refreshed (with " + lock.getQueueLength() + " already waiting)");
				
				if(lock.tryLock(refreshTimeout, TimeUnit.MILLISECONDS)) {
					try {
						// see if anyone already refreshed the cache while we were
						// hold getting the lock
						if (cache == this.cache) {
							// Seems cache was not updated.
							// We hold the lock, so safe to update it now
							LOGGER.warning("JWK cache was NOT successfully refreshed while waiting, retry now (with " + lock.getQueueLength() + " waiting)..");

							cache = loadJWKSetFromProvider(time);
							
							LOGGER.info("JWK cache refreshed (with " + lock.getQueueLength() + " waiting)");
						} else {
							// load updated value
							LOGGER.info("JWK cache was successfully refreshed while waiting");
							
							cache = this.cache;
						}
					} finally {
						lock.unlock();
					}
				} else {
					throw new JWKSetUnavailableException("Timeout while waiting for refreshed cache (limit of " + refreshTimeout + "ms exceed).");
				}
			}

			if (cache != null && cache.isValid(time)) {
				return cache;
			}

			throw new JWKSetUnavailableException("Unable to refresh cache");
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt(); // Restore interrupted state to make sonar happy

			throw new JWKSetUnavailableException("Interrupted while waiting for refreshed cache", e);
		}
	}

	/**
	 * Load Jwks from wrapped provider. Guaranteed to only run for one thread at a time.
	 *
	 * @param time current time
	 * @return cache item
	 * @throws JwksException if loading could not be performed
	 */

	protected JWKSetCacheItem loadJWKSetFromProvider(long time) throws KeySourceException {
		JWKSet all = provider.getJWKSet(false);

		// save to cache
		return this.cache = new JWKSetCacheItem(all, getExpires(time));
	}

	ReentrantLock getLock() {
		return lock;
	}
}
