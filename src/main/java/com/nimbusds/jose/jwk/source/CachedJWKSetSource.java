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

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Caching {@linkplain JWKSetSource}. Blocks when the cache is updated.
 */

public class CachedJWKSetSource<C extends SecurityContext, L extends CachedJWKSetSource.Listener<C>> extends AbstractCachedJWKSetSource<C> {

	public static interface Listener<C extends SecurityContext> extends JWKSetSourceListener<C> {
		
		void onPendingCacheRefresh(int queueLength, C context);
		void onCacheRefreshed(int jwksCount, int queueLength, C context);
		
		void onUnableToRefreshCache(C context);
		
		void onWaitingForCacheRefresh(long timeout, int queueLength, C context);
		void onTimeoutWaitingForCacheRefresh(long timeout, int queueLength, C context);
		
	}
	
	protected final ReentrantLock lock = new ReentrantLock();

	protected final long refreshTimeout;
	
	protected final L listener;
	/**
	 * Construct new instance.
	 * 
	 * @param source	     JWK set source
	 * @param timeToLive	 cache hold time (in milliseconds)
	 * @param refreshTimeout cache refresh timeout unit
	 */

	public CachedJWKSetSource(JWKSetSource<C> source, long timeToLive, long refreshTimeout, L listener) {
		super(source, timeToLive);

		this.refreshTimeout = refreshTimeout;
		this.listener = listener;
	}

	public JWKSet getJWKSet(long currentTime, boolean forceUpdate, C context) throws KeySourceException {
		JWKSetCacheItem cache = this.cache;
		if (cache == null || (forceUpdate && cache.getTimestamp() < currentTime) || !cache.isValid(currentTime)) {
			cache = getJwksBlocking(currentTime, context);
		}

		return cache.getValue();
	}

	protected JWKSetCacheItem getJwksBlocking(long currentTime, C context) throws KeySourceException {
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

		JWKSetCacheItem cache = null;
		try {
			if(lock.tryLock()) {
				try {
					// see if anyone already refreshed the cache while we were
					// hold getting the lock
					if (!isCacheUpdatedSince(currentTime)) {
						// Seems cache was not updated.
						// We hold the lock, so safe to update it now
						listener.onPendingCacheRefresh(lock.getQueueLength(), context);

						JWKSetCacheItem result = loadJWKSetFromSource(currentTime, context);

						listener.onCacheRefreshed(result.getValue().size(), lock.getQueueLength(), context);
						
						cache = result;
					} else {
						// load updated value
						cache = this.cache;
					}
				} finally {
					lock.unlock();
				}
			} else {
				listener.onWaitingForCacheRefresh(refreshTimeout, lock.getQueueLength(), context);

				if(lock.tryLock(refreshTimeout, TimeUnit.MILLISECONDS)) {
					try {
						// see if anyone already refreshed the cache while we were
						// hold getting the lock
						if (!isCacheUpdatedSince(currentTime)) {
							// Seems cache was not updated.
							// We hold the lock, so safe to update it now
							listener.onPendingCacheRefresh(lock.getQueueLength(), context);
							
							cache = loadJWKSetFromSource(currentTime, context);
							
							listener.onCacheRefreshed(cache.getValue().size() , lock.getQueueLength(), context);
						} else {
							// load updated value
							cache = this.cache;
						}
					} finally {
						lock.unlock();
					}
				} else {
					listener.onTimeoutWaitingForCacheRefresh(refreshTimeout, lock.getQueueLength(), context);

					throw new JWKSetUnavailableException("Timeout while waiting for refreshed cache (limit of " + refreshTimeout + "ms exceed).");
				}
			}

			if (cache != null && cache.isValid(currentTime)) {
				return cache;
			}

			listener.onUnableToRefreshCache(context);
			
			throw new JWKSetUnavailableException("Unable to refresh cache");
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt(); // Restore interrupted state to make sonar happy

			throw new JWKSetUnavailableException("Interrupted while waiting for refreshed cache", e);
		}
	}

	protected boolean isCacheUpdatedSince(long time) {
		JWKSetCacheItem latest = this.cache;
		if(latest == null) {
			return false;
		}
		return time <= latest.getTimestamp();
	}

	/**
	 * Load JWKs from wrapped source. Guaranteed to only run for one thread at a time.
	 *
	 * @param currentTime current time
	 * @return cache item
	 * @throws JwksException if loading could not be performed
	 */

	protected JWKSetCacheItem loadJWKSetFromSource(long currentTime, C context) throws KeySourceException {
		JWKSet all = source.getJWKSet(currentTime, false, context);

		JWKSetCacheItem cache = createJWKSetCacheItem(all, currentTime);
		
		this.cache = cache;
		
		return cache;
	}

	ReentrantLock getLock() {
		return lock;
	}
}
