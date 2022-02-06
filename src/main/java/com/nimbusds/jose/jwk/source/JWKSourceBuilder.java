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

/**
 * JwkProvider builder
 * 
 * @see <a href=
 *	  "https://www.sitepoint.com/self-types-with-javas-generics/">https://www.sitepoint.com/self-types-with-javas-generics/</a>
 */

public class JWKSourceBuilder<C extends SecurityContext> {

	/**
	 * The default HTTP connect timeout for JWK set retrieval, in
	 * milliseconds. Set to 500 milliseconds.
	 */
	public static final int DEFAULT_HTTP_CONNECT_TIMEOUT = 500;

	/**
	 * The default HTTP read timeout for JWK set retrieval, in
	 * milliseconds. Set to 500 milliseconds.
	 */
	public static final int DEFAULT_HTTP_READ_TIMEOUT = 500;

	/**
	 * The default HTTP entity size limit for JWK set retrieval, in bytes.
	 * Set to 50 KBytes.
	 */
	public static final int DEFAULT_HTTP_SIZE_LIMIT = 50 * 1024;

	/**
	 * Resolves the default HTTP connect timeout for JWK set retrieval, in
	 * milliseconds.
	 *
	 * @return The {@link #DEFAULT_HTTP_CONNECT_TIMEOUT static constant},
	 *		 overridden by setting the
	 *		 {@code com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpConnectTimeout}
	 *		 Java system property.
	 */
	public static int resolveDefaultHTTPConnectTimeout() {
		return resolveDefault(RemoteJWKSet.class.getName() + ".defaultHttpConnectTimeout", DEFAULT_HTTP_CONNECT_TIMEOUT);
	}

	/**
	 * Resolves the default HTTP read timeout for JWK set retrieval, in
	 * milliseconds.
	 *
	 * @return The {@link #DEFAULT_HTTP_READ_TIMEOUT static constant},
	 *		 overridden by setting the
	 *		 {@code com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpReadTimeout}
	 *		 Java system property.
	 */
	public static int resolveDefaultHTTPReadTimeout() {
		return resolveDefault(RemoteJWKSet.class.getName() + ".defaultHttpReadTimeout", DEFAULT_HTTP_READ_TIMEOUT);
	}

	/**
	 * Resolves default HTTP entity size limit for JWK set retrieval, in
	 * bytes.
	 *
	 * @return The {@link #DEFAULT_HTTP_SIZE_LIMIT static constant},
	 *		 overridden by setting the
	 *		 {@code com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpSizeLimit}
	 *		 Java system property.
	 */
	public static int resolveDefaultHTTPSizeLimit() {
		return resolveDefault(RemoteJWKSet.class.getName() + ".defaultHttpSizeLimit", DEFAULT_HTTP_SIZE_LIMIT);
	}

	private static int resolveDefault(final String sysPropertyName, final int defaultValue) {

		String value = System.getProperty(sysPropertyName);

		if (value == null) {
			return defaultValue;
		}

		try {
			return Integer.parseInt(value);
		} catch (NumberFormatException e) {
			// Illegal value
			return defaultValue;
		}
	}

	public static <C extends SecurityContext> JWKSourceBuilder<C> newBuilder(URL url, ResourceRetriever resourceRetriever) {
		return new JWKSourceBuilder<>(new ResourceRetrieverJWKSetProvider(url, resourceRetriever));
	}

	public static <C extends SecurityContext> JWKSourceBuilder<C> newBuilder(URL url, final int connectTimeout, final int readTimeout, final int sizeLimit) {
		DefaultResourceRetriever jwkSetRetriever = new DefaultResourceRetriever(
				connectTimeout,
				readTimeout,
				sizeLimit);
		return new JWKSourceBuilder<>(new ResourceRetrieverJWKSetProvider(url, jwkSetRetriever));
	}

	public static <C extends SecurityContext> JWKSourceBuilder<C> newBuilder(URL url) {
		DefaultResourceRetriever jwkSetRetriever = new DefaultResourceRetriever(
				resolveDefaultHTTPConnectTimeout(),
				resolveDefaultHTTPReadTimeout(),
				resolveDefaultHTTPSizeLimit());
		return new JWKSourceBuilder<>(new ResourceRetrieverJWKSetProvider(url, jwkSetRetriever));
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
	// a single request for every refill duration
	// (retry on network error does not count)
	protected boolean rateLimited = true;
	protected long refillDuration = 30 * 1000;

	// retrying
	protected boolean retrying = false;

	// outage
	protected boolean outageCached = false;
	protected long outageCachedDuration = cacheDuration * 10;

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
		this.preemptiveRefresh = false;
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
	 * Enable the shadow cache specifying size and expire time.
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

		if (retrying) {
			provider = new RetryingJWKSetProvider(provider);
		}
		if (outageCached) {
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

		RemoteJWKSet<C> jwkSource = new RemoteJWKSet<>(provider);
		if(failover != null) {
			return new FailoverJWKSource<>(jwkSource, failover);
		}
		return jwkSource;
	}

}
