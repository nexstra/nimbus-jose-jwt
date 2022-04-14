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


import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.cache.CachedObject;


/**
 * Caching {@linkplain JWKSetSource}. Blocks during cache updates.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-09
 */
@ThreadSafe
public class CachingJWKSetSource<C extends SecurityContext, L extends CachingJWKSetSource.Listener<C>> extends AbstractCachingJWKSetSource<C> {

	public interface Listener<C extends SecurityContext> extends JWKSetSourceListener<C> {
		
		void onPendingCacheRefresh(int queueLength, C context);
		void onCacheRefreshed(int jwksCount, int queueLength, C context);
		
		void onUnableToRefreshCache(C context);
		
		void onWaitingForCacheRefresh(long timeout, int queueLength, C context);
		void onTimeoutWaitingForCacheRefresh(long timeout, int queueLength, C context);
	}
	
	private final ReentrantLock lock = new ReentrantLock();

	private final long cacheRefreshTimeout;
	
	protected final L listener;
	
	
	/**
	 * Creates a new caching JWK set source.
	 * 
	 * @param source	      The JWK set source to decorate. Must not
	 *                            be {@code null}.
	 * @param timeToLive          The time to live of the cached JWK set,
	 * 	                      in milliseconds.
	 * @param cacheRefreshTimeout The cache refresh timeout, in
	 *                            milliseconds.
	 * @param listener            The listener, {@code null} if not
	 *                            specified.
	 */
	public CachingJWKSetSource(final JWKSetSource<C> source, final long timeToLive, final long cacheRefreshTimeout, final L listener) {
		super(source, timeToLive);
		this.cacheRefreshTimeout = cacheRefreshTimeout;
		this.listener = listener;
	}

	
	@Override
	public JWKSet getJWKSet(final boolean forceReload, final long currentTime, final C context) throws KeySourceException {
		CachedObject<JWKSet> cache = getCachedJWKSet();
		if (cache == null || (forceReload && cache.getTimestamp() < currentTime) || cache.isExpired(currentTime)) {
			return loadJWKSetBlocking(currentTime, context);
		}
		return cache.get();
	}
	
	
	/**
	 * Returns the cache refresh timeout.
	 *
	 * @return The cache refresh timeout, in milliseconds.
	 */
	public long getCacheRefreshTimeout() {
		return cacheRefreshTimeout;
	}
	
	
	/**
	 * Loads and caches the JWK set, with blocking.
	 *
	 * @param currentTime The current time, in milliseconds since the Unix
	 *                    epoch.
	 * @param context     Optional context, {@code null} if not required.
	 *
	 * @return The loaded and cached JWK set.
	 *
	 * @throws KeySourceException If retrieval failed.
	 */
	JWKSet loadJWKSetBlocking(final long currentTime, final C context)
		throws KeySourceException {
		
		// Synchronize so that the first thread to acquire the lock
		// exclusively gets to call the underlying source.
		// Other (later) threads must wait until the result is ready.
		//
		// If the first to get the lock fails within the waiting interval,
		// subsequent threads will attempt to update the cache themselves.
		//
		// This approach potentially blocks a number of threads,
		// but requesting the same data downstream is not better, so
		// this is a necessary evil.

		final CachedObject<JWKSet> cache;
		try {
			if (lock.tryLock()) {
				try {
					// see if anyone already refreshed the cache while we were
					// getting the lock
					if (! isCacheUpdatedSince(currentTime)) {
						// Seems cache was not updated.
						// We hold the lock, so safe to update it now
						if (listener != null) {
							listener.onPendingCacheRefresh(lock.getQueueLength(), context);
						}
						
						CachedObject<JWKSet> result = loadJWKSetNotThreadSafe(currentTime, context);

						if (listener != null) {
							listener.onCacheRefreshed(result.get().size(), lock.getQueueLength(), context);
						}
						
						cache = result;
					} else {
						// load updated value
						cache = getCachedJWKSet();
					}
				} finally {
					lock.unlock();
				}
			} else {
				if (listener != null) {
					listener.onWaitingForCacheRefresh(getCacheRefreshTimeout(), lock.getQueueLength(), context);
				}

				if (lock.tryLock(getCacheRefreshTimeout(), TimeUnit.MILLISECONDS)) {
					try {
						// see if anyone already refreshed the cache while we were
						// waiting to get hold of the lock
						if (! isCacheUpdatedSince(currentTime)) {
							// Seems cache was not updated.
							// We hold the lock, so safe to update it now
							if (listener != null) {
								listener.onPendingCacheRefresh(lock.getQueueLength(), context);
							}
							
							cache = loadJWKSetNotThreadSafe(currentTime, context);
							
							if (listener != null) {
								listener.onCacheRefreshed(cache.get().size(), lock.getQueueLength(), context);
							}
						} else {
							// load updated value
							cache = getCachedJWKSet();
						}
					} finally {
						lock.unlock();
					}
				} else {
					if (listener != null) {
						listener.onTimeoutWaitingForCacheRefresh(getCacheRefreshTimeout(), lock.getQueueLength(), context);
					}

					throw new JWKSetUnavailableException("Timeout while waiting for refreshed cache (limit of " + cacheRefreshTimeout + "ms exceed).");
				}
			}

			if (cache != null && cache.isValid(currentTime)) {
				return cache.get();
			}

			if (listener != null) {
				listener.onUnableToRefreshCache(context);
			}
			
			throw new JWKSetUnavailableException("Unable to refresh cache");
			
		} catch (InterruptedException e) {
			
			Thread.currentThread().interrupt(); // Restore interrupted state to make Sonar happy

			throw new JWKSetUnavailableException("Interrupted while waiting for cache refresh", e);
		}
	}
	
	
	private boolean isCacheUpdatedSince(final long time) {
		CachedObject<JWKSet> latest = getCachedJWKSet();
		if(latest == null) {
			return false;
		}
		return time <= latest.getTimestamp();
	}
	
	
	/**
	 * Loads the JWK set from the wrapped source and caches it. Should not
	 * be run by more than one thread at a time.
	 *
	 * @param currentTime The current time, in milliseconds since the Unix
	 *                    epoch.
	 *
	 * @return Reference to the cached JWK set.
	 *
	 * @throws KeySourceException If loading failed.
	 */
	CachedObject<JWKSet> loadJWKSetNotThreadSafe(final long currentTime, final C context)
		throws KeySourceException {
		
		JWKSet jwkSet = getSource().getJWKSet(false, currentTime, context);

		return cacheJWKSet(jwkSet, currentTime);
	}
	
	
	/**
	 * Returns the lock.
	 *
	 * @return The lock.
	 */
	ReentrantLock getLock() {
		return lock;
	}
}
