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


import java.net.URL;
import java.util.Objects;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;


/**
 * {@linkplain JWKSource} builder.
 *
 * TODO explain usage and defaults
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-14
 */
public class JWKSourceBuilder<C extends SecurityContext> {
	
	// Implementation comment TODO is this applicable?
	// https://www.sitepoint.com/self-types-with-javas-generics/
	
	
	/**
	 * TODO
	 */
	public static <C extends SecurityContext> JWKSourceBuilder<C> newBuilder(final URL url) {
		
		
		// TODO consider copying deprecating constants here
		DefaultResourceRetriever retriever = new DefaultResourceRetriever(
			RemoteJWKSet.DEFAULT_HTTP_CONNECT_TIMEOUT,
			RemoteJWKSet.DEFAULT_HTTP_READ_TIMEOUT,
			RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT);
		
		JWKSetSource<C> jwkSetSource = new URLBasedJWKSetSource<>(url, retriever);
		
		return new JWKSourceBuilder<>(jwkSetSource);
	}
	
	
	/**
	 * TODO
	 */
	public static <C extends SecurityContext> JWKSourceBuilder<C> newBuilder(final URL url, final ResourceRetriever retriever) {
		return new JWKSourceBuilder<>(new URLBasedJWKSetSource<C>(url, retriever));
	}
	
	
	/**
	 * TODO
	 */
	public static <C extends SecurityContext> JWKSourceBuilder<C> newBuilder(final JWKSetSource<C> source) {
		return new JWKSourceBuilder<>(source);
	}

	// root source
	private final JWKSetSource<C> jwkSetSource;

	// cache
	private boolean caching = true;
	private long cacheTimeToLive = 5 * 60 * 1000; // TODO make explicit constants
	private long cacheRefreshTimeout = 15 * 1000;
	private CachingJWKSetSource.Listener<C> cachingJWKSetSourceListener;

	private boolean refreshAhead = true;
	private long refreshAheadTime = 30 * 1000;
	private boolean refreshAheadScheduled = false;
	private RefreshAheadCachingJWKSetSource.Listener<C> refreshAheadCachingJWKSetSourceListener;

	// rate limiting (up to 2 request per interval, retry on network error will not count against this)
	protected boolean rateLimited = true;
	protected long minTimeInterval = 30 * 1000;
	protected RateLimitedJWKSetSource.Listener<C> rateLimitedJWKSetSourceListener;

	// retrying
	protected boolean retrying = false;
	protected RetryingJWKSetSource.Listener<C> retryingJWKSetSourceListener;

	// outage
	protected boolean outageTolerant = false;
	protected long outageCacheTimeToLive = -1L;
	protected OutageTolerantJWKSetSource.Listener<C> outageTolerantJWKSetSourceListener;

	// health status reporting
	protected boolean health = true;
	protected JWKSetSourceWithHealthStatusReporting.Listener<C> jwkSetSourceWithHealthStatusReportingListener;

	// failover
	protected JWKSource<C> failover;
	

	/**
	 * Wraps the specified {@linkplain JWKSetSource} for further
	 * decoration.
	 *
	 * @param jwkSetSource The JWK set source to wrap. Must not be
	 *                     {@code null}.
	 */
	JWKSourceBuilder(final JWKSetSource<C> jwkSetSource) {
		Objects.requireNonNull(jwkSetSource);
		this.jwkSetSource = jwkSetSource;
	}

	
	/**
	 * Toggles caching of the JWK set.
	 *
	 * @param enable {@code true} to cache the JWK set.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> cache(final boolean enable) {
		this.caching = enable;
		return this;
	}
	
	
	/**
	 * Toggles caching of the JWK set.
	 *
	 * @param enable   {@code true} to cache the JWK set.
	 * @param listener The cache event listener, {@code null} if not
	 *                 specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> cache(final boolean enable, final CachingJWKSetSource.Listener<C> listener) {
		this.caching = enable;
		this.cachingJWKSetSourceListener = listener;
		return this;
	}


	/**
	 * Enables caching of the retrieved JWK set.
	 * 
	 * @param timeToLive          The time to live of the cached JWK set,
	 *                            in milliseconds.
	 * @param cacheRefreshTimeout The cache refresh timeout, in
	 *                            milliseconds.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> cache(final long timeToLive, final long cacheRefreshTimeout) {
		this.caching = true;
		this.cacheTimeToLive = timeToLive;
		this.cacheRefreshTimeout = cacheRefreshTimeout;
		return this;
	}
	
	
	/**
	 * Enables caching of the retrieved JWK set.
	 *
	 * @param timeToLive          The time to live of the cached JWK set,
	 *                            in milliseconds.
	 * @param cacheRefreshTimeout The cache refresh timeout, in
	 *                            milliseconds.
	 * @param listener            The cache event listener, {@code null} if
	 *                            not specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> cache(final long timeToLive, final long cacheRefreshTimeout, final CachingJWKSetSource.Listener<C> listener) {
		this.caching = true;
		this.cacheTimeToLive = timeToLive;
		this.cacheRefreshTimeout = cacheRefreshTimeout;
		this.cachingJWKSetSourceListener = listener;
		return this;
	}


	/**
	 * Enables caching of the JWK set forever (no expiration).
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> cacheForever() {
		this.caching = true;
		this.cacheTimeToLive = Long.MAX_VALUE;
		// refresh ahead not necessary
		this.refreshAhead = false;
		return this;
	}
	
	
	/**
	 * Enables caching of the JWK set forever (no expiration).
	 *
	 * @param listener The cache event listener, {@code null} if not
	 *                 specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> cacheForever(final CachingJWKSetSource.Listener<C> listener) {
		this.caching = true;
		this.cacheTimeToLive = Long.MAX_VALUE;
		this.cachingJWKSetSourceListener = listener;
		// refresh ahead not necessary
		this.refreshAhead = false;
		return this;
	}
	
	
	/**
	 * Toggles refresh-ahead caching of the JWK set.
	 *
	 * @param enable {@code true} to enable refresh-ahead caching of the
	 *               JWK set.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> refreshAheadCache(final boolean enable) {
		if (enable) {
			this.caching = true;
		}
		this.refreshAhead = enable;
		return this;
	}
	
	
	/**
	 * Enables refresh-ahead caching of the JWK set.
	 *
	 * @param refreshAheadTime The refresh ahead time, in milliseconds.
	 * @param scheduled        {@code true} to refresh in a scheduled
	 *                         manner, regardless of requests.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> refreshAheadCache(final long refreshAheadTime, final boolean scheduled) {
		this.caching = true;
		this.refreshAhead = true;
		this.refreshAheadTime = refreshAheadTime;
		this.refreshAheadScheduled = scheduled;
		return this;
	}

	
	/**
	 * Enables refresh-ahead caching of the JWK set.
	 *
	 * @param refreshAheadTime The refresh ahead time, in milliseconds.
	 * @param scheduled        {@code true} to refresh in a scheduled
	 *                         manner, regardless of requests.
	 * @param listener         The refresh-ahead cache event listener,
	 *                         {@code null} if not specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> refreshAheadCache(final long refreshAheadTime, final boolean scheduled, final RefreshAheadCachingJWKSetSource.Listener<C> listener) {
		this.caching = true;
		this.refreshAhead = true;
		this.refreshAheadTime = refreshAheadTime;
		this.refreshAheadScheduled = scheduled;
		this.refreshAheadCachingJWKSetSourceListener = listener;
		return this;
	}
	
	
	/**
	 * Toggles refresh-ahead caching of the JWK set.
	 *
	 * @param refreshAhead {@code true} to enable refresh-ahead caching of
	 *                     the JWK set.
	 * @param listener     The refresh-ahead cache event listener,
	 *                     {@code null} if not specified.
	 *                                                                             
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> refreshAheadCache(final boolean refreshAhead, final RefreshAheadCachingJWKSetSource.Listener<C> listener) {
		if (refreshAhead) {
			this.caching = true;
		}
		this.refreshAhead = refreshAhead;
		this.refreshAheadCachingJWKSetSourceListener = listener;
		return this;
	}


	/**
	 * Toggles rate limiting of the JWK set retrieval.
	 *
	 * @param enable {@code true} to rate limit the JWK set retrieval.
	 *                           
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> rateLimited(final boolean enable) {
		this.rateLimited = enable;
		return this;
	}
	

	/**
	 * Toggles rate limiting of the JWK set retrieval.
	 *
	 * @param enable   {@code true} to rate limit the JWK set retrieval.
	 * @param listener The rate limit event listener, {@code null} if not
	 *                 specified.
	 *                           
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> rateLimited(final boolean enable, final RateLimitedJWKSetSource.Listener<C> listener) {
		this.rateLimited = enable;
		this.rateLimitedJWKSetSourceListener = listener;
		return this;
	}

	
	/**
	 * Enables rate limiting of the JWK set retrieval.
	 *
	 * @param minTimeInterval The minimum allowed time interval between two
	 *                        JWK set retrievals, in milliseconds.
	 *
	 * @return This builder.
	 */

	public JWKSourceBuilder<C> rateLimited(final long minTimeInterval) {
		this.rateLimited = true;
		this.minTimeInterval = minTimeInterval;
		return this;
	}
	
	
	/**
	 * Toggles rate limiting of the JWK set retrieval.
	 *
	 * @param minTimeInterval The minimum allowed time interval between two
	 *                        JWK set retrievals, in milliseconds.
	 * @param listener        The rate limit event listener, {@code null}
	 *                        if not specified.
	 *
	 * @return This builder.
	 */

	public JWKSourceBuilder<C> rateLimited(final long minTimeInterval, final RateLimitedJWKSetSource.Listener<C> listener) {
		this.rateLimited = true;
		this.minTimeInterval = minTimeInterval;
		this.rateLimitedJWKSetSourceListener = listener;
		return this;
	}
	
	
	/**
	 * Sets a failover JWK source.
	 *
	 * @param failover The failover JWK source, {@code null} if none.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> failover(final JWKSource<C> failover) {
		this.failover = failover;
		return this;
	}
	
	
	/**
	 * Enables single retrial to retrieve the JWK set to work around
	 * transient network issues.
	 * 
	 * @param enable {@code true} to enable single retrial.
	 *
	 * @return This builder.
	 */

	public JWKSourceBuilder<C> retrying(final boolean enable) {
		this.retrying = enable;
		return this;
	}

	
	/**
	 * Enable retry-one upon transient network problems. 
	 * 
	 * @param enable   {@code true} to enable single retrial.
	 * @param listener The retrial event listener, {@code null} if not
	 *                 specified.
	 *
	 * @return This builder.
	 */
	
	public JWKSourceBuilder<C> retrying(final boolean enable, final RetryingJWKSetSource.Listener<C> listener) {
		this.retrying = enable;
		this.retryingJWKSetSourceListener = listener;
		return this;
	}

	
	/**
	 * Toggles health status reporting.
	 *
	 * @param enabled {@code true} to enable health status reporting.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> healthReporting(final boolean enabled) {
		this.health = enabled;
		return this;
	}
	
	
	/**
	 * Toggles health status reporting.
	 *
	 * @param enabled  {@code true} to enable health status reporting.
	 * @param listener The health status event listener, {@code null} if
	 *                 not specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> healthReporting(final boolean enabled, final JWKSetSourceWithHealthStatusReporting.Listener<C> listener) {
		this.health = enabled;
		this.jwkSetSourceWithHealthStatusReportingListener = listener;
		return this;
	}
	
	
	/**
	 * Toggles outage tolerance by serving a cached JWK set in case of
	 * outage.
	 *
	 * @param enabe {@code true} to enable the outage cache.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> outageTolerant(final boolean enabe) {
		this.outageTolerant = enabe;
		return this;
	}
	
	
	/**
	 * Toggles outage tolerance by serving a cached JWK set in case of
	 * outage.
	 *
	 * @param enable   {@code true} to enable the outage cache.
	 * @param listener The outage event listener, {@code null} if not
	 *                 specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> outageTolerant(final boolean enable, final OutageTolerantJWKSetSource.Listener<C> listener) {
		this.outageTolerant = enable;
		this.outageTolerantJWKSetSourceListener = listener;
		return this;
	}

	
	/**
	 * Enables outage tolerance by serving a non-expiring cached JWK set in
	 * case of outage.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> outageTolerantForever() {
		this.outageTolerant = true;
		this.outageCacheTimeToLive = Long.MAX_VALUE;
		return this;
	}

	
	/**
	 * Enables outage tolerance by serving a non-expiring cached JWK set in
	 * case of outage.
	 *
	 * @param listener The outage event listener, {@code null} if not
	 *                 specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> outageTolerantForever(final OutageTolerantJWKSetSource.Listener<C> listener) {
		this.outageTolerant = true;
		this.outageCacheTimeToLive = Long.MAX_VALUE;
		this.outageTolerantJWKSetSourceListener = listener;
		return this;
	}
	
	
	/**
	 * Enables outage tolerance by serving a non-expiring cached JWK set in
 	 * case of outage.
	 *
	 * @param timeToLive The time to live of the cached JWK set to cover
	 *                   outages, in milliseconds.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> outageTolerant(final long timeToLive) {
		this.outageTolerant = true;
		this.outageCacheTimeToLive = timeToLive;
		return this;
	}

	
	/**
	 * Enables outage tolerance by serving a non-expiring cached JWK set in
	 * case of outage.
	 *
	 * @param timeToLive The time to live of the cached JWK set to cover
	 *                   outages, in milliseconds.
	 * @param listener   The outage event listener, {@code null} if not
	 *                   specified.
	 *
	 * @return This builder.
	 */
	public JWKSourceBuilder<C> outageTolerant(final long timeToLive, final OutageTolerantJWKSetSource.Listener<C> listener) {
		this.outageTolerant = true;
		this.outageCacheTimeToLive = timeToLive;
		this.outageTolerantJWKSetSourceListener = listener;
		return this;
	}

	
	/**
	 * Builds the final {@link JWKSource}.
	 *
	 * @return The final {@link JWKSource}.
	 */
	public JWKSource<C> build() {
		
		if (! caching && rateLimited) {
			throw new IllegalStateException("Rate limiting requires caching");
		} else if (! caching && refreshAhead) {
			throw new IllegalStateException("Refresh-ahead caching requires general caching");
		}

		if (caching && rateLimited && cacheTimeToLive <= minTimeInterval) {
			throw new IllegalStateException("The rate limiting min time interval between requests must be less than the cache time-to-live");
		}
		
		if (caching && outageTolerant && cacheTimeToLive == Long.MAX_VALUE && outageCacheTimeToLive == Long.MAX_VALUE) {
			throw new IllegalStateException("Outage tolerance not necessary with a non-expiring cache");
		}

		if (caching && refreshAhead && cacheTimeToLive == Long.MAX_VALUE) {
			throw new IllegalStateException("Refresh-ahead caching not necessary with a non-expiring cache");
		}
		
		JWKSetSource<C> source = jwkSetSource;

		if (retrying) {
			source = new RetryingJWKSetSource<>(source, retryingJWKSetSourceListener);
		}
		
		if (outageTolerant) {
			if (outageCacheTimeToLive == -1L) {
				if (caching) {
					outageCacheTimeToLive = cacheTimeToLive * 10;
				} else {
					outageCacheTimeToLive = 5 * 60 * 1000 * 10;
				}
			}
			source = new OutageTolerantJWKSetSource<>(source, outageCacheTimeToLive, outageTolerantJWKSetSourceListener);
		}

		JWKSetSourceWithHealthStatusReporting<C> healthSource = null;
		if (health) {
			source = healthSource = new JWKSetSourceWithHealthStatusReporting<>(source, jwkSetSourceWithHealthStatusReportingListener);
		}

		if (rateLimited) {
			source = new RateLimitedJWKSetSource<>(source, minTimeInterval, rateLimitedJWKSetSourceListener);
		}
		if (refreshAhead) {
			source = new RefreshAheadCachingJWKSetSource<>(source, cacheTimeToLive, cacheRefreshTimeout, refreshAheadTime, refreshAheadScheduled, refreshAheadCachingJWKSetSourceListener);
		} else if (caching) {
			source = new CachingJWKSetSource<>(source, cacheTimeToLive, cacheRefreshTimeout, cachingJWKSetSourceListener);
		}
		if (health) {
			// the heath source needs a reference to the top-level source
			healthSource.setTopLevelSource(source);
		}

		JWKSource<C> jwkSource = new JWKSetBasedJWKSource<>(source);
		if (failover != null) {
			return new JWKSourceWithFailover<>(jwkSource, failover);
		}
		return jwkSource;
	}
}
