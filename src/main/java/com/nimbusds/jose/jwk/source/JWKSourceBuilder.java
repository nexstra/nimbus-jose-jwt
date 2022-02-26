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

import com.nimbusds.jose.jwk.source.OutageCachedJWKSetSource.Listener;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;

import java.net.URL;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * {@linkplain JWKSource} builder
 * 
 * @see <a href=
 *	  "https://www.sitepoint.com/self-types-with-javas-generics/">https://www.sitepoint.com/self-types-with-javas-generics/</a>
 */

public class JWKSourceBuilder<C extends SecurityContext> {

	public static <C extends SecurityContext> JWKSourceBuilder<C> newBuilder(URL url, ResourceRetriever resourceRetriever) {
		return new JWKSourceBuilder<>(new ResourceRetrieverJWKSetSource<C>(url, resourceRetriever));
	}

	public static <C extends SecurityContext> JWKSourceBuilder<C> newBuilder(URL url) {
		JWKSetSource<C> jwkSetSource;
		
		String protocol = url.getProtocol();
		if(Objects.equals(protocol, "file")) {
			jwkSetSource = new LocalUrlJWKSetSource<>(url);
		} else {
			DefaultResourceRetriever jwkSetRetriever = new DefaultResourceRetriever(
					RemoteJWKSet.DEFAULT_HTTP_CONNECT_TIMEOUT,
					RemoteJWKSet.DEFAULT_HTTP_READ_TIMEOUT,
					RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT);
			
			jwkSetSource = new ResourceRetrieverJWKSetSource<>(url, jwkSetRetriever);
		}
		return new JWKSourceBuilder<>(jwkSetSource);
	}
	
	public static <C extends SecurityContext> JWKSourceBuilder<C> newBuilder(JWKSetSource<C> source) {
		return new JWKSourceBuilder<>(source);
	}

	// root source
	protected final JWKSetSource<C> jwkSetSource;

	// cache
	protected boolean cached = true;
	protected long cacheDuration = 5 * 60 * 1000;
	protected long cacheRefreshTimeoutDuration = 15 * 1000;
	protected CachedJWKSetSource.Listener<C> cachedJWKSetSourceListener;

	protected boolean preemptiveRefresh = true;
	protected long preemptiveRefreshDuration = 30 * 1000;
	protected boolean preemptiveRefreshEager = false;
	protected PreemptiveCachedJWKSetSource.Listener<C> preemptiveCachedJWKSetSourceListener;

	// rate limiting
	// Max two requests for every refill duration
	// (retry on network error will not count against this)
	protected boolean rateLimited = true;
	protected long refillDuration = 30 * 1000;
	protected RateLimitedJWKSetSource.Listener<C> rateLimitedJWKSetSourceListener;

	// retrying
	protected boolean retrying = false;
	protected RetryingJWKSetSource.Listener<C> retryingJWKSetSourceListener;

	// outage
	protected boolean outageCached = false;
	protected long outageCachedDuration = -1L;
	protected OutageCachedJWKSetSource.Listener<C> outageCachedJWKSetSourceListener;

	// health indicator support
	protected boolean health = true;
	protected JWKSetHealthSourceListener<C> jwkSetHealthSourceListener;

	protected JWKSource<C> failover;

	/**
	 * Wrap a specific {@linkplain JWKSetSource}. Access to this instance will be
	 * cached and/or rate-limited according to the configuration of this builder.
	 *
	 * @param jwkSetSource root JWK set source
	 */

	JWKSourceBuilder(JWKSetSource<C> jwkSetSource) {
		this.jwkSetSource = jwkSetSource;
	}

	/**
	 * Toggle the cache of JWK. By default the source will use cache.
	 *
	 * @param cached if the source should cache jwks
	 * @return the builder
	 */
	public JWKSourceBuilder<C> cached(boolean cached) {
		this.cached = cached;
		return this;
	}
	
	/**
	 * Toggle the cache of JWK. By default the source will use cache.
	 *
	 * @param cached if the source should cache jwks
	 * @return the builder
	 */
	public JWKSourceBuilder<C> cached(boolean cached, CachedJWKSetSource.Listener<C> listener) {
		this.cached = cached;
		this.cachedJWKSetSourceListener = listener;
		return this;
	}


	/**
	 * Enable the cache specifying size, expire time and maximum wait time for cache
	 * refresh.
	 * 
	 * @param expires			cache hold time
	 * @param refreshExpires	 cache refresh timeout
	 * @return the builder
	 */
	
	public JWKSourceBuilder<C> cached(long expires, long refreshExpires) {
		this.cached = true;
		this.cacheDuration = expires;
		this.cacheRefreshTimeoutDuration = refreshExpires;
		return this;
	}
	
	/**
	 * Enable the cache specifying size, expire time and maximum wait time for cache
	 * refresh.
	 * 
	 * @param expires			cache hold time
	 * @param refreshExpires	 cache refresh timeout
	 * @return the builder
	 */
	
	public JWKSourceBuilder<C> cached(long expires, long refreshExpires, CachedJWKSetSource.Listener<C> listener) {
		this.cached = true;
		this.cacheDuration = expires;
		this.cacheRefreshTimeoutDuration = refreshExpires;
		this.cachedJWKSetSourceListener = listener;
		return this;
	}


	/**
	 * Toggle the cache of JWKs. By default the source will use cache.
	 *
	 * @param cached if the source should cache JWKs
	 * @return the builder
	 */
	public JWKSourceBuilder<C> cachedForever() {
		this.cached = true;
		this.cacheDuration = Long.MAX_VALUE;
		
		// preemptive will never be necessary
		this.preemptiveRefresh = false;
		return this;
	}
	
	/**
	 * Toggle the cache of JWKs. By default the source will use cache.
	 *
	 * @param cached if the source should cache JWKs
	 * @param listener {@linkplain CachedJWKSetSource.Listener} listener
	 * @return the builder
	 */
	public JWKSourceBuilder<C> cachedForever(CachedJWKSetSource.Listener<C> listener) {
		this.cached = true;
		this.cacheDuration = Long.MAX_VALUE;
		this.cachedJWKSetSourceListener = listener;
		// preemptive will never be necessary
		this.preemptiveRefresh = false;
		return this;
	}

	/**
	 * Enable the preemptive cache. This also enables caching.
	 *
	 * @param duration Preemptive limit, relative to cache time to live, i.e. "15
	 *			  seconds before timeout, refresh time cached value".
	 * @param eager Refresh the token even if there is no traffic (otherwise will be on demand).
	 *			  
	 * @return the builder
	 */
	public JWKSourceBuilder<C> preemptiveCacheRefresh(long duration, boolean eager) {
		this.cached = true;
		this.preemptiveRefresh = true;
		this.preemptiveRefreshDuration = duration;
		this.preemptiveRefreshEager = eager;
		return this;
	}

	
	/**
	 * Enable the preemptive cache. This also enables caching.
	 *
	 * @param duration Preemptive limit, relative to cache time to live, i.e. "15
	 *			  seconds before timeout, refresh time cached value".
	 * @param eager Refresh the token even if there is no traffic (otherwise will be on demand).
	 * @param listener {@linkplain PreemptiveCachedJWKSetSource.Listener} listener
	 *			  
	 * @return the builder
	 */
	public JWKSourceBuilder<C> preemptiveCacheRefresh(long duration, boolean eager, PreemptiveCachedJWKSetSource.Listener<C> listener) {
		this.cached = true;
		this.preemptiveRefresh = true;
		this.preemptiveRefreshDuration = duration;
		this.preemptiveRefreshEager = eager;
		this.preemptiveCachedJWKSetSourceListener = listener;
		return this;
	}

	
	/**
	 * Enable the preemptive cache. This also enables caching.
	 *
	 * @param preemptive if true, preemptive caching is active
	 * @return the builder
	 */
	public JWKSourceBuilder<C> preemptiveCacheRefresh(boolean preemptive) {
		if (preemptive) {
			this.cached = true;
		}
		this.preemptiveRefresh = preemptive;
		return this;
	}
	
	/**
	 * Enable the preemptive cache. This also enables caching.
	 *
	 * @param preemptive if true, preemptive caching is active
	 * @param listener {@linkplain PreemptiveCachedJWKSetSource.Listener} listener
	 * @return the builder
	 */
	public JWKSourceBuilder<C> preemptiveCacheRefresh(boolean preemptive, PreemptiveCachedJWKSetSource.Listener<C> listener) {
		if (preemptive) {
			this.cached = true;
		}
		this.preemptiveRefresh = preemptive;
		this.preemptiveCachedJWKSetSourceListener = listener;
		return this;
	}


	/**
	 * Toggle the rate limit of JWK refresh. By default the source will use rate limit.
	 *
	 * @param rateLimited if the source should rate limit jwks
	 * @param listener {@linkplain RateLimitedJWKSetSource.Listener} listener
	 * @return the builder
	 */
	public JWKSourceBuilder<C> rateLimited(boolean rateLimited) {
		this.rateLimited = rateLimited;
		return this;
	}
	

	/**
	 * Toggle the rate limit of JWK refresh. By default the source will use rate limit.
	 *
	 * @param rateLimited if the source should rate limit jwks
	 * @return the builder
	 */
	public JWKSourceBuilder<C> rateLimited(boolean rateLimited, RateLimitedJWKSetSource.Listener<C> listener) {
		this.rateLimited = rateLimited;
		this.rateLimitedJWKSetSourceListener = listener;
		return this;
	}

	/**
	 * Enable the cache rate-limiting. Rate-limiting is important to protect
	 * downstream authorization servers because unknown keys will cause the list to
	 * be reloaded; making it a vector for stressing this and the authorization
	 * service.
	 *
	 * @param refillDuration duration between refills 
	 * @return the builder
	 */

	public JWKSourceBuilder<C> rateLimited(long refillDuration) {
		this.rateLimited = true;
		this.refillDuration = refillDuration;
		return this;
	}
	
	/**
	 * Enable the cache ratelimiting. Rate-limiting is important to protect
	 * downstream authorization servers because unknown keys will cause the list to
	 * be reloaded; making it a vector for stressing this and the authorization
	 * service.
	 *
	 * @param refillDuration duration between refills 
	 * @param listener {@linkplain RateLimitedJWKSetSource.Listener} listener
	 * @return the builder
	 */

	public JWKSourceBuilder<C> rateLimited(long refillDuration, RateLimitedJWKSetSource.Listener<C> listener) {
		this.rateLimited = true;
		this.refillDuration = refillDuration;
		this.rateLimitedJWKSetSourceListener = listener;
		return this;
	}

	public JWKSourceBuilder<C> failover(JWKSource<C> failover) {
		this.failover = failover;
		return this;
	}
	
	/**
	 * Enable retry-one upon transient network problems. 
	 * 
	 * @param retrying true if enabled
	 * @return the builder
	 */

	public JWKSourceBuilder<C> retrying(boolean retrying) {
		this.retrying = retrying;

		return this;
	}

	/**
	 * Enable retry-one upon transient network problems. 
	 * 
	 * @param retrying true if enabled
	 * @param listener {@linkplain RetryingJWKSetSource.Listener} listener
	 * @return the builder
	 */
	
	public JWKSourceBuilder<C> retrying(boolean retrying, RetryingJWKSetSource.Listener<C> listener) {
		this.retrying = retrying;
		this.retryingJWKSetSourceListener = listener;
		return this;
	}

	/**
	 * Toggle the health status. By default this option is enabled.
	 *
	 * @param enabled true if the health status source should be enabled
	 * @return the builder
	 */
	public JWKSourceBuilder<C> health(boolean enabled) {
		this.health = enabled;
		return this;
	}
	
	public JWKSourceBuilder<C> health(boolean enabled, JWKSetHealthSourceListener<C> listener) {
		this.health = enabled;
		this.jwkSetHealthSourceListener = listener;
		return this;
	}
	
	/**
	 * Toggle the outage cache. By default the source will not use an outage
	 * cache.
	 *
	 * @param outageCached if the outage cache is enabled
	 * @return the builder
	 */
	public JWKSourceBuilder<C> outageCached(boolean outageCached) {
		this.outageCached = outageCached;
		return this;
	}
	
	/**
	 * Toggle the outage cache. By default the source will not use an outage
	 * cache.
	 *
	 * @param outageCached if the outage cache is enabled
	 * @param listener {@linkplain OutageCachedJWKSetSource.Listener} listener
	 * @return the builder
	 */
	public JWKSourceBuilder<C> outageCached(boolean outageCached, OutageCachedJWKSetSource.Listener<C> listener) {
		this.outageCached = outageCached;
		this.outageCachedJWKSetSourceListener = listener;
		return this;
	}

	/**
	 * Enable never-expiring outage cache. In other words, as long as the
	 * JWKs cannot be transferred / read from the source, typically 
	 * due to network issues or service malfunction, the last certificates are to be used.
	 *
	 * @param outageCached if the outage cache is enabled
	 * @return the builder
	 */
	public JWKSourceBuilder<C> outageCachedForever() {
		this.outageCached = true;
		this.outageCachedDuration = Long.MAX_VALUE;
		return this;
	}

	/**
	 * Enable never-expiring outage cache. In other words, as long as the
	 * JWKs cannot be transferred / read from the source, typically 
	 * due to network issues or service malfunction, the last certificates are to be used.
	 *
	 * @param outageCached if the outage cache is enabled
	 * @param listener {@linkplain OutageCachedJWKSetSource.Listener} listener
	 * @return the builder
	 */
	public JWKSourceBuilder<C> outageCachedForever(OutageCachedJWKSetSource.Listener<C> listener) {
		this.outageCached = true;
		this.outageCachedDuration = Long.MAX_VALUE;
		this.outageCachedJWKSetSourceListener = listener;
		return this;
	}
	
	/**
	 * Enable the outage cache specifying size and expire time.
	 *
	 * @param duration amount of time the jwk will be cached
	 * @return the builder
	 */
	public JWKSourceBuilder<C> outageCached(long duration) {
		this.outageCached = true;
		this.outageCachedDuration = duration;
		return this;
	}

	/**
	 * Enable the outage cache specifying size and expire time.
	 *
	 * @param duration amount of time the jwk will be cached
	 * @param listener {@linkplain OutageCachedJWKSetSource.Listener} listener
	 * @return the builder
	 */
	public JWKSourceBuilder<C> outageCached(long duration, OutageCachedJWKSetSource.Listener<C> listener) {
		this.outageCached = true;
		this.outageCachedDuration = duration;
		this.outageCachedJWKSetSourceListener = listener;
		return this;
	}


	
	/**
	 * Creates a {@link JWKSource}
	 *
	 * @return a newly created {@link JWKSource}
	 */
	public JWKSource<C> build() {
		JWKSetSource<C> source = jwkSetSource;

		if (!cached && rateLimited) {
			throw new IllegalStateException("Ratelimiting configured without caching");
		} else if (!cached && preemptiveRefresh) {
			throw new IllegalStateException("Premptive cache refresh configured without caching");
		}

		if(cached && rateLimited && cacheDuration <= refillDuration) {
			throw new IllegalStateException("Ratelimit refill duration must be less than cache duration");
		}
		
		if(cached && outageCached && cacheDuration == Long.MAX_VALUE && outageCachedDuration == Long.MAX_VALUE) {
			throw new IllegalStateException("No outage protection is necessary if cache never expires");
		}

		if(cached && preemptiveRefresh && cacheDuration == Long.MAX_VALUE) {
			throw new IllegalStateException("No preemptie cache refresh is necessary if cache never expires");
		}

		if (retrying) {
			if(retryingJWKSetSourceListener != null) {
				retryingJWKSetSourceListener = new DefaultRetryingJWKSetSourceListener<>(Level.FINER);
			}
			source = new RetryingJWKSetSource<>(source, retryingJWKSetSourceListener);
		}
		
		if (outageCached) {
			if(outageCachedDuration == -1L) {
				if(cached) {
					outageCachedDuration = cacheDuration * 10;
				} else {
					outageCachedDuration = 5 * 60 * 1000 * 10; 
				}
			}
			if(outageCachedJWKSetSourceListener == null) {
				outageCachedJWKSetSourceListener = new DefaultOutageCachedJWKSetSourceListener<>(Level.INFO, Level.WARNING);
			}
			source = new OutageCachedJWKSetSource<>(source, outageCachedDuration, outageCachedJWKSetSourceListener);
		}

		DefaultHealthJWKSetSource<C> healthSource = null;
		if (health) {
			if(jwkSetHealthSourceListener == null) {
				jwkSetHealthSourceListener = new DefaultJWKSetHealthSourceListener<>(Level.FINER);
			}
			source = healthSource = new DefaultHealthJWKSetSource<>(source, jwkSetHealthSourceListener);
		}

		if (rateLimited) {
			if(rateLimitedJWKSetSourceListener == null) {
				rateLimitedJWKSetSourceListener = new DefaultRateLimitedJWKSetSourceListener<>(Level.FINER);
			}
			source = new RateLimitedJWKSetSource<>(source, refillDuration, rateLimitedJWKSetSourceListener);
		}
		if (preemptiveRefresh) {
			if(preemptiveCachedJWKSetSourceListener == null) {
				preemptiveCachedJWKSetSourceListener = new DefaultPreemptiveCachedJWKSetSourceListener<>(Level.FINER);
			}
			
			source = new PreemptiveCachedJWKSetSource<>(source, cacheDuration, cacheRefreshTimeoutDuration, preemptiveRefreshDuration, preemptiveRefreshEager, preemptiveCachedJWKSetSourceListener);
		} else if (cached) {
			
			if(cachedJWKSetSourceListener == null) {
				cachedJWKSetSourceListener = new DefaultCachedJWKSetSourceListener<>(Level.FINER);
			}
			source = new CachedJWKSetSource<>(source, cacheDuration, cacheRefreshTimeoutDuration, cachedJWKSetSourceListener);
		}
		if (health) {
			// set the top level on the health source, for refreshing from the top.
			healthSource.setRefreshSource(source);
		}

		JWKSource<C> jwkSource = new UrlJWKSource<>(source);
		if(failover != null) {
			return new FailoverJWKSource<>(jwkSource, failover);
		}
		return jwkSource;
	}

}
