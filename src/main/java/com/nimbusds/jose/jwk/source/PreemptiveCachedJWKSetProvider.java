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

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Caching {@linkplain JWKSetProvider} which preemptively attempts to update the
 * cache in the background. The preemptive updates themselves run on a separate,
 * dedicated thread. Updates can be (eagerly) continuously scheduled, or (lazily)
 * triggered by incoming requests for JWKs. <br>
 * <br>
 * <p>
 * This class is intended for uninterrupted operation in high-load scenarios, as
 * it will avoid a (potentially) large number of threads blocking when the cache
 * expires (and must be refreshed).<br>
 * <br>
 */

public class PreemptiveCachedJWKSetProvider extends DefaultCachedJWKSetProvider {

	private static final Logger LOGGER = Logger.getLogger(PreemptiveCachedJWKSetProvider.class.getName());

	// preemptive update should execute when
	// expire - preemptiveRefresh < current time < expire.
	private final long preemptiveRefresh; // milliseconds

	private final ReentrantLock lazyLock = new ReentrantLock();

	private final ExecutorService executorService;
	private final boolean shutdownExecutorOnClose;

	private final ScheduledExecutorService scheduledExecutorService;
	
	// cache expire time is used as its fingerprint
	private volatile long cacheExpires;
	
	private ScheduledFuture<?> eagerScheduledFuture;

	/**
	 * Construct new instance.
	 *
	 * @param provider		  JWKSet provider
	 * @param timeToLive		cache hold time (in milliseconds)
	 * @param refreshTimeout	cache refresh timeout unit (in milliseconds), i.e. before giving up
	 * @param preemptiveRefresh preemptive timeout (in milliseconds). This parameter
	 *						  is relative to time to live, i.e. "15000
	 *						  milliseconds before timeout, refresh time cached
	 *						  value".
	 * @param eager			 preemptive refresh even if no traffic (schedule update)
	 */

	public PreemptiveCachedJWKSetProvider(JWKSetProvider provider, long timeToLive, long refreshTimeout, long preemptiveRefresh, boolean eager) {
		this(provider, timeToLive, refreshTimeout, preemptiveRefresh, eager, Executors.newSingleThreadExecutor(), true);
	}

	/**
	 * Construct new instance, use a custom executor service.
	 *
	 * @param provider				JWKSet provider
	 * @param timeToLive			  cache hold time (in milliseconds)
	 * @param refreshTimeout		  cache refresh timeout unit (in milliseconds), i.e. before giving up
	 * @param preemptiveRefresh	   preemptive refresh limit (in milliseconds). This
	 *								parameter is relative to time to live, i.e. "15000
	 *								milliseconds before timeout, refresh time cached
	 *								value".
	 * @param eager				   preemptive refresh even if no traffic (schedule update)
	 * @param executorService		 executor service
	 * @param shutdownExecutorOnClose Whether to shutdown the executor service on calls to close(..).
	 */

	public PreemptiveCachedJWKSetProvider(JWKSetProvider provider, long timeToLive, long refreshTimeout, long preemptiveRefresh, boolean eager, ExecutorService executorService, boolean shutdownExecutorOnClose) {
		super(provider, timeToLive, refreshTimeout);

		if (preemptiveRefresh + refreshTimeout > timeToLive) {
			throw new IllegalArgumentException("Time to live (" + timeToLive/1000 + "s) must exceed preemptive refresh limit (" + preemptiveRefresh/1000 + "s) + the refresh timeout (" + refreshTimeout/1000 + "s) (as in the max duration of the refresh operation itself)");
		}

		this.preemptiveRefresh = preemptiveRefresh;
		this.executorService = executorService;
		this.shutdownExecutorOnClose = shutdownExecutorOnClose;

		if(eager) {
			scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
		} else {
			scheduledExecutorService = null;
		}
	}

	@Override
	public JWKSet getJWKSet(long currentTime, boolean forceUpdate) throws KeySourceException {
		JWKSetCacheItem cache = this.cache;
		if (cache == null || (forceUpdate && cache.getTimestamp() < currentTime) || !cache.isValid(currentTime)) {
			return super.getJwksBlocking(currentTime).getValue();
		}
		preemptiveRefresh(currentTime, cache, false);

		return cache.getValue();
	}

	@Override
	protected JWKSetCacheItem loadJWKSetFromProvider(long currentTime) throws KeySourceException {
		// note: never run by two threads at the same time
		JWKSetCacheItem cache = super.loadJWKSetFromProvider(currentTime);

		if (scheduledExecutorService != null) {
			schedulePreemptiveRefresh(currentTime, cache);
		}

		return cache;
	}

	protected void schedulePreemptiveRefresh(long currentTime, final JWKSetCacheItem cache) {
		if (eagerScheduledFuture != null) {
			eagerScheduledFuture.cancel(false);
		}

		// so we want to keep other threads from triggering preemptive refreshing
		// subtracting the refresh timeout should be enough
		long delay = cache.getExpires() - currentTime - preemptiveRefresh - refreshTimeout;
		if (delay > 0) {
			Runnable command = new Runnable() {

				@Override
				public void run() {
					try {
						// so will only refresh if this specific cache entry still is the current one
						preemptiveRefresh(System.currentTimeMillis(), cache, true);
					} catch (Exception e) {
						LOGGER.log(Level.WARNING, "Scheduled eager JWKs refresh failed", e);
					}
				}
			};
			this.eagerScheduledFuture = scheduledExecutorService.schedule(command, delay, TimeUnit.MILLISECONDS);

			LOGGER.info("Scheduled next eager JWKs refresh in " + getTime(delay));
		} else {
			LOGGER.log(Level.WARNING, "Not scheduling eager JWKs refresh");
		}
	}

	protected String getTime(long update) {
		return Long.toString(update);
	}

	/**
	 * Preemptive update, on a background thread.
	 *
	 * @param time  current time
	 * @param cache current cache (non-null)
	 */

	protected void preemptiveRefresh(final long time, final JWKSetCacheItem cache, boolean forceRefresh) {
		if (!cache.isValid(time + preemptiveRefresh) || forceRefresh) {
			// cache will expire soon,
			// preemptively update it

			// check if an update is already in progress
			if (cacheExpires < cache.getExpires()) {
				// seems no update is in progress, see if we can get the lock
				if (lazyLock.tryLock()) {
					try {
						lockedPreemptiveRefresh(time, cache);
					} finally {
						lazyLock.unlock();
					}
				}
			}
		}
	}

	/**
	 * Check if preemptive refresh is in progress, and if not trigger a preemptive refresh.
	 * This method is called by a single thread at a time.
	 *
	 * @param time  current time
	 * @param cache current cache
	 */

	protected void lockedPreemptiveRefresh(final long time, final JWKSetCacheItem cache) {
		// check if an update is already in progress (again now that this thread holds the lock)
		if (cacheExpires < cache.getExpires()) {

			// still no update is in progress
			cacheExpires = cache.getExpires();

			Runnable runnable = new Runnable() {

				@Override
				public void run() {
					try {
						LOGGER.info("Perform preemptive JWKs refresh");
						PreemptiveCachedJWKSetProvider.this.getJwksBlocking(time);

						// so next time this method is invoked, it'll be with the updated cache item expiry time
					} catch (Throwable e) {
						// update failed, but another thread can retry
						cacheExpires = -1L;
						// ignore, unable to update
						// another thread will attempt the same
						LOGGER.log(Level.WARNING, "Preemptive JWKs refresh failed", e);
					}
				}
			};
			// run update in the background
			executorService.execute(runnable);
		}
	}


	/**
	 * Return the executor service which handles the background refresh.
	 *
	 * @return executor service
	 */

	public ExecutorService getExecutorService() {
		return executorService;
	}

	ReentrantLock getLazyLock() {
		return lazyLock;
	}
	
	ScheduledFuture<?> getEagerScheduledFuture() {
		return eagerScheduledFuture;
	}

	@Override
	public void close() throws IOException {
		ScheduledFuture<?> eagerJwkListCacheItem = this.eagerScheduledFuture; // defensive copy
		if(eagerJwkListCacheItem != null) {
			eagerJwkListCacheItem.cancel(true);
			LOGGER.info("Cancelled scheduled JWKs refresh");
		}
		
		super.close();
		
		if(shutdownExecutorOnClose) {
			executorService.shutdownNow();
			try {
				executorService.awaitTermination(refreshTimeout, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				// ignore
				LOGGER.log(Level.INFO, "Interrupted while waiting for executor shutdown", e);
				Thread.currentThread().interrupt();
			}
		}
		if(scheduledExecutorService != null) {
			scheduledExecutorService.shutdownNow();
			try {
				scheduledExecutorService.awaitTermination(refreshTimeout, TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				// ignore
				LOGGER.log(Level.INFO, "Interrupted while waiting for scheduled executor shutdown", e);
				Thread.currentThread().interrupt();
			}
		}		
	}
}
