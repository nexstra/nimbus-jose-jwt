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

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;

import java.net.URL;
import java.util.Objects;

/**
 * JwkProvider builder
 * 
 * @see <a href=
 *	  "https://www.sitepoint.com/self-types-with-javas-generics/">https://www.sitepoint.com/self-types-with-javas-generics/</a>
 */

public class JWKSourceBuilder<C extends SecurityContext> {

	public static <C extends SecurityContext> JWKSourceBuilder<C> newBuilder(URL url, ResourceRetriever resourceRetriever) {
		return new JWKSourceBuilder<>(new ResourceRetrieverJWKSetProvider(url, resourceRetriever));
	}

	public static <C extends SecurityContext> JWKSourceBuilder<C> newBuilder(URL url) {
		JWKSetProvider jwkSetProvider;
		
		String protocol = url.getProtocol();
		if(Objects.equals(protocol, "file")) {
			jwkSetProvider = new LocalUrlJWKSetProvider(url);
		} else {
			DefaultResourceRetriever jwkSetRetriever = new DefaultResourceRetriever(
					RemoteJWKSet.DEFAULT_HTTP_CONNECT_TIMEOUT,
					RemoteJWKSet.DEFAULT_HTTP_READ_TIMEOUT,
					RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT);
			
			jwkSetProvider = new ResourceRetrieverJWKSetProvider(url, jwkSetRetriever);
		}
		return new JWKSourceBuilder<>(jwkSetProvider);
	}
	
	public static <C extends SecurityContext> JWKSourceBuilder<C> newBuilder(JWKSetProvider provider) {
		return new JWKSourceBuilder<>(provider);
	}

	// root provider
	protected final JWKSetProvider jwkSetProvider;

	// cache
	protected boolean cached = true;
	protected long cacheDuration = 5 * 60 * 1000;
	protected long cacheRefreshTimeoutDuration = 15 * 1000;

	protected boolean preemptiveRefresh = true;
	protected long preemptiveRefreshDuration = 30 * 1000;
	protected boolean preemptiveRefreshEager = false;

	// rate limiting
	// Max two requests for every refill duration
	// (retry on network error will not count against this)
	protected boolean rateLimited = true;
	protected long refillDuration = 30 * 1000;

	// retrying
	protected boolean retrying = false;

	// outage
	protected boolean outageCached = false;
	protected long outageCachedDuration = -1L;

	// health indicator support
	protected boolean health = true;

	protected JWKSource<C> failover;

	/**
	 * Wrap a specific {@linkplain JWKSetProvider}. Access to this instance will be
	 * cached and/or rate-limited according to the configuration of this builder.
	 *
	 * @param jwkSetProvider root JwksProvider
	 */

	JWKSourceBuilder(JWKSetProvider jwkSetProvider) {
		this.jwkSetProvider = jwkSetProvider;
	}

	/**
	 * Toggle the cache of Jwk. By default the provider will use cache.
	 *
	 * @param cached if the provider should cache jwks
	 * @return the builder
	 */
	public JWKSourceBuilder<C> cached(boolean cached) {
		this.cached = cached;
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
	 * Toggle the cache of Jwk. By default the provider will use cache.
	 *
	 * @param cached if the provider should cache jwks
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
	 * Toggle the rate limit of Jwk. By default the Provider will use rate limit.
	 *
	 * @param rateLimited if the provider should rate limit jwks
	 * @return the builder
	 */
	public JWKSourceBuilder<C> rateLimited(boolean rateLimited) {
		this.rateLimited = rateLimited;
		return this;
	}

	/**
	 * Enable the cache ratelimiting. Rate-limiting is important to protect
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

	public JWKSourceBuilder<C> failover(JWKSource<C> failover) {
		this.failover = failover;
		return this;
	}

	protected JWKSetProvider getRateLimitedProvider(JWKSetProvider provider) {
		return new RateLimitedJWKSetProvider(provider, refillDuration);
	}

	public JWKSourceBuilder<C> retrying(boolean retrying) {
		this.retrying = retrying;

		return this;
	}

	/**
	 * Toggle the health status. By default this option is enabled.
	 *
	 * @param enabled true if the health status provider should be enabled
	 * @return the builder
	 */
	public JWKSourceBuilder<C> health(boolean enabled) {
		this.health = enabled;
		return this;
	}

	/**
	 * Toggle the outage cache. By default the Provider will not use an outage
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
	 * Creates a {@link JWKSource}
	 *
	 * @return a newly created {@link JWKSource}
	 */
	public JWKSource<C> build() {
		JWKSetProvider provider = jwkSetProvider;

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
			provider = new RetryingJWKSetProvider(provider);
		}
		
		if (outageCached) {
			if(outageCachedDuration == -1L) {
				// TODO what is a sane default value here
				if(cached) {
					outageCachedDuration = cacheDuration * 10;
				} else {
					outageCachedDuration = 5 * 60 * 1000 * 10; 
				}
			}
			provider = new OutageCachedJWKSetProvider(provider, outageCachedDuration);
		}

		DefaultHealthJWKSetProvider healthProvider = null;
		if (health) {
			provider = healthProvider = new DefaultHealthJWKSetProvider(provider);
		}

		if (rateLimited) {
			provider = getRateLimitedProvider(provider);
		}
		if (preemptiveRefresh) {
			provider = new PreemptiveCachedJWKSetProvider(provider, cacheDuration, cacheRefreshTimeoutDuration, preemptiveRefreshDuration, preemptiveRefreshEager);
		} else if (cached) {
			provider = new DefaultCachedJWKSetProvider(provider, cacheDuration, cacheRefreshTimeoutDuration);
		}
		if (health) {
			// set the top level on the health provider, for refreshing from the top.
			healthProvider.setRefreshProvider(provider);
		}

		JWKSource<C> jwkSource = new UrlJWKSource<>(provider);
		if(failover != null) {
			return new FailoverJWKSource<>(jwkSource, failover);
		}
		return jwkSource;
	}

}
