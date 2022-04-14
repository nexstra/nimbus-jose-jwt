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


import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.cache.CachedObject;


/**
 * Caching {@linkplain JWKSetSource} that refreshes the JWK set prior to its
 * expiration. The updates run on a separate, dedicated thread. Updates can be
 * repeatedly scheduled, or (lazily) triggered by incoming requests for the JWK
 * set.
 *
 * <p>This class is intended for uninterrupted operation under high-load, to
 * avoid a (potentially) large number of threads blocking when the cache
 * expires (and must be refreshed).
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-09
 */
@ThreadSafe
public class RefreshAheadCachingJWKSetSource<C extends SecurityContext> extends CachingJWKSetSource<C, RefreshAheadCachingJWKSetSource.Listener<C>> {

	public interface Listener<C extends SecurityContext> extends CachingJWKSetSource.Listener<C> {
		
		void onCacheRefreshScheduled(long time, C context);

		void onCacheRefreshNotScheduled(C context);

		void onScheduledCacheRefreshFailed(Exception e, C context);

		void onInitiatedCacheRefreshAheadOfExpiration(C context);

		void onCacheRefreshedAheadOfExpiration(C context);

		void onUnableToRefreshCacheAheadOfExpiration(C context);
	}
	
	// refresh ahead of expiration should execute when
	// expirationTime - refreshAheadTime < currentTime < expirationTime
	private final long refreshAheadTime; // milliseconds

	private final ReentrantLock lazyLock = new ReentrantLock();

	private final ExecutorService executorService;
	private final boolean shutdownExecutorOnClose;
	private final ScheduledExecutorService scheduledExecutorService;
	
	// cache expiration time (in milliseconds) used as fingerprint
	private volatile long cacheExpiration;
	
	private ScheduledFuture<?> scheduledRefreshFuture;

	
	/**
	 * Creates a new refresh-ahead caching JWK set source.
	 *
	 * @param source	      The JWK set source to decorate. Must not
	 *                            be {@code null}.
	 * @param timeToLive          The time to live of the cached JWK set,
	 * 	                      in milliseconds.
	 * @param cacheRefreshTimeout The cache refresh timeout, in
	 *                            milliseconds.
	 * @param refreshAheadTime    The refresh ahead time, in milliseconds.
	 * @param scheduled           {@code true} to refresh in a scheduled
	 *                            manner, regardless of requests.
	 * @param listener            The listener, {@code null} if not
	 *                            specified.
	 */
	public RefreshAheadCachingJWKSetSource(final JWKSetSource<C> source,
					       final long timeToLive,
					       final long cacheRefreshTimeout,
					       final long refreshAheadTime,
					       final boolean scheduled,
					       final Listener<C> listener) {
		
		this(source, timeToLive, cacheRefreshTimeout, refreshAheadTime,
			scheduled, Executors.newSingleThreadExecutor(), true, listener);
	}
	

	/**
	 * Creates a new refresh-ahead caching JWK set source with the
	 * specified executor service to run the updates in the background.
	 *
	 * @param source	          The JWK set source to decorate. Must
	 *                                not be {@code null}.
	 * @param timeToLive              The time to live of the cached JWK
	 *                                set, in milliseconds.
	 * @param cacheRefreshTimeout     The cache refresh timeout, in
	 *                                milliseconds.
	 * @param refreshAheadTime        The refresh ahead time, in
	 *                                milliseconds.
	 * @param scheduled               {@code true} to refresh in a
	 *                                scheduled manner, regardless of
	 *                                requests.
	 * @param executorService         The executor service to run the
	 *                                updates in the background.
	 * @param shutdownExecutorOnClose If {@code true} the executor service
	 *                                will be shut down upon closing the
	 *                                source.
	 * @param listener                The listener, {@code null} if not
	 *                                specified.
	 */
	public RefreshAheadCachingJWKSetSource(final JWKSetSource<C> source,
					       final long timeToLive,
					       final long cacheRefreshTimeout,
					       final long refreshAheadTime,
					       final boolean scheduled,
					       final ExecutorService executorService,
					       final boolean shutdownExecutorOnClose,
					       final Listener<C> listener) {
		
		super(source, timeToLive, cacheRefreshTimeout, listener);

		if (refreshAheadTime + cacheRefreshTimeout > timeToLive) {
			throw new IllegalArgumentException("The sum of the refresh-ahead time (" + refreshAheadTime +"ms) " +
				"and the cache refresh timeout (" + cacheRefreshTimeout +"ms) " +
				"must not exceed the time-to-lived time (" + timeToLive + "ms)");
		}

		this.refreshAheadTime = refreshAheadTime;
		
		Objects.requireNonNull(executorService, "The executor service must not be null");
		this.executorService = executorService;
		
		this.shutdownExecutorOnClose = shutdownExecutorOnClose;

		if (scheduled) {
			scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
		} else {
			scheduledExecutorService = null;
		}
	}

	
	@Override
	public JWKSet getJWKSet(final boolean forceReload, final long currentTime, final C context) throws KeySourceException {
		CachedObject<JWKSet> cache = getCachedJWKSet();
		if (cache == null || (forceReload && cache.getTimestamp() < currentTime) || cache.isExpired(currentTime)) {
			return super.loadJWKSetBlocking(currentTime, context);
		}
		refreshAheadOfExpiration(cache, false, currentTime, context);

		return cache.get();
	}
	

	@Override
	CachedObject<JWKSet> loadJWKSetNotThreadSafe(final long currentTime, final C context) throws KeySourceException {
		// Never run by two threads at the same time!
		CachedObject<JWKSet> cache = super.loadJWKSetNotThreadSafe(currentTime, context);

		if (scheduledExecutorService != null) {
			scheduleRefreshAheadOfExpiration(cache, currentTime, context);
		}

		return cache;
	}
	
	
	/**
	 * Schedules repeated refresh ahead of cached JWK set expiration.
	 */
	void scheduleRefreshAheadOfExpiration(final CachedObject<JWKSet> cache, final long currentTime, final C context) {
		
		if (scheduledRefreshFuture != null) {
			scheduledRefreshFuture.cancel(false);
		}

		// so we want to keep other threads from triggering preemptive refresh
		// subtracting the refresh timeout should be enough
		long delay = cache.getExpirationTime() - currentTime - refreshAheadTime - getCacheRefreshTimeout();
		if (delay > 0) {
			Runnable command = new Runnable() {

				@Override
				public void run() {
					try {
						// so will only refresh if this specific cache entry still is the current one
						refreshAheadOfExpiration(cache, true, System.currentTimeMillis(), context);
					} catch (Exception e) {
						if (listener != null) {
							listener.onScheduledCacheRefreshFailed(e, context);
						}
					}
				}
			};
			this.scheduledRefreshFuture = scheduledExecutorService.schedule(command, delay, TimeUnit.MILLISECONDS);

			if (listener != null) {
				listener.onCacheRefreshScheduled(delay, context);
			}
		} else {
			if (listener != null) {
				listener.onCacheRefreshNotScheduled(context);
			}
		}
	}

	
	/**
	 * Refreshes the cached JWK set if past the time threshold or refresh
	 * is forced.
	 *
	 * @param cache        The current cache. Must not be {@code null}.
	 * @param forceRefresh {@code true} to force refresh.
	 * @param currentTime  The current time.
	 */
	void refreshAheadOfExpiration(final CachedObject<JWKSet> cache, final boolean forceRefresh, final long currentTime, final C context) {
		
		if (cache.isExpired(currentTime + refreshAheadTime) || forceRefresh) {
			
			// cache will expire soon, preemptively update it

			// check if an update is already in progress
			if (cacheExpiration < cache.getExpirationTime()) {
				// seems no update is in progress, see if we can get the lock
				if (lazyLock.tryLock()) {
					try {
						lockedRefresh(cache, currentTime, context);
					} finally {
						lazyLock.unlock();
					}
				}
			}
		}
	}

	
	/**
	 * Checks if a refresh is in progress and if not triggers one. To be
	 * called by a single thread at a time.
	 *
	 * @param cache       The current cache. Must not be {@code null}.
	 * @param currentTime The current time.
	 */
	void lockedRefresh(final CachedObject<JWKSet> cache, final long currentTime, final C context) {
		// check if an update is already in progress (again now that this thread holds the lock)
		if (cacheExpiration < cache.getExpirationTime()) {

			// still no update is in progress
			cacheExpiration = cache.getExpirationTime();

			Runnable runnable = new Runnable() {

				@Override
				public void run() {
					try {
						if (listener != null) {
							listener.onInitiatedCacheRefreshAheadOfExpiration(context);
						}
						
						RefreshAheadCachingJWKSetSource.this.loadJWKSetBlocking(currentTime, context);

						if (listener != null) {
							listener.onCacheRefreshedAheadOfExpiration(context);
						}

						// so next time this method is invoked, it'll be with the updated cache item expiry time
					} catch (Throwable e) {
						// update failed, but another thread can retry
						cacheExpiration = -1L;
						// ignore, unable to update
						// another thread will attempt the same
						if (listener != null) {
							listener.onUnableToRefreshCacheAheadOfExpiration(context);
						}
					}
				}
			};
			// run update in the background
			executorService.execute(runnable);
		}
	}


	/**
	 * Returns the executor service running the updates in the background.
	 *
	 * @return The executor service.
	 */
	public ExecutorService getExecutorService() {
		return executorService;
	}

	
	ReentrantLock getLazyLock() {
		return lazyLock;
	}
	
	
	/**
	 * Returns the current scheduled refresh future.
	 *
	 * @return The current future, {@code null} if none.
	 */
	ScheduledFuture<?> getScheduledRefreshFuture() {
		return scheduledRefreshFuture;
	}

	
	@Override
	public void close() throws IOException {
		
		ScheduledFuture<?> currentScheduledRefreshFuture = this.scheduledRefreshFuture; // defensive copy
		if (currentScheduledRefreshFuture != null) {
			currentScheduledRefreshFuture.cancel(true);
		}
		
		super.close();
		
		if (shutdownExecutorOnClose) {
			executorService.shutdownNow();
			try {
				executorService.awaitTermination(getCacheRefreshTimeout(), TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				// ignore
				Thread.currentThread().interrupt();
			}
		}
		if (scheduledExecutorService != null) {
			scheduledExecutorService.shutdownNow();
			try {
				scheduledExecutorService.awaitTermination(getCacheRefreshTimeout(), TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				// ignore
				Thread.currentThread().interrupt();
			}
		}		
	}
}
