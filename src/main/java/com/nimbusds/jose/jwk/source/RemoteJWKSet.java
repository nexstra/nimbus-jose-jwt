/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
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
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;


/**
 * Remote JSON Web Key (JWK) source specified by a JWK set URL. The retrieved
 * JWK set is cached to minimise network calls. The cache is updated whenever
 * the key selector tries to get a key with an unknown ID or the cache expires.
 *
 * <p>If no {@link ResourceRetriever} is specified when creating a remote JWK
 * set source the {@link DefaultResourceRetriever default one} will be used,
 * with the following HTTP timeouts and limits:
 *
 * <ul>
 *     <li>HTTP connect timeout, in milliseconds: Determined by the
 *         {@link #DEFAULT_HTTP_CONNECT_TIMEOUT} constant which can be
 *         overridden by setting the
 *         {@code com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpConnectTimeout}
 * 	   Java system property.
 *     <li>HTTP read timeout, in milliseconds: Determined by the
 *         {@link #DEFAULT_HTTP_READ_TIMEOUT} constant which can be
 *         overridden by setting the
 *         {@code com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpReadTimeout}
 * 	   Java system property.
 *     <li>HTTP entity size limit: Determined by the
 *         {@link #DEFAULT_HTTP_SIZE_LIMIT} constant which can be
 *         overridden by setting the
 *         {@code com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpSizeLimit}
 * 	   Java system property.
 * </ul>
 *
 * <p>A failover JWK source can be configured in case the JWK set URL becomes
 * unavailable (HTTP 404) or times out. The failover JWK source can be another
 * URL or some other object.
 *
 * @author Vladimir Dzhuvinov
 * @author Andreas Huber
 * @version 2022-01-30
 * @deprecated Prefer to construct a {@linkplain JWKSource} using {@linkplain JWKSourceBuilder}.
 */
@ThreadSafe
@Deprecated
public class RemoteJWKSet<C extends SecurityContext> implements JWKSource<C> {


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
	 *         overridden by setting the
	 *         {@code com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpConnectTimeout}
	 *         Java system property.
	 */
	public static int resolveDefaultHTTPConnectTimeout() {
		return resolveDefault(RemoteJWKSet.class.getName() + ".defaultHttpConnectTimeout", DEFAULT_HTTP_CONNECT_TIMEOUT);
	}
	
	
	/**
	 * Resolves the default HTTP read timeout for JWK set retrieval, in
	 * milliseconds.
	 *
	 * @return The {@link #DEFAULT_HTTP_READ_TIMEOUT static constant},
	 *         overridden by setting the
	 *         {@code com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpReadTimeout}
	 *         Java system property.
	 */
	public static int resolveDefaultHTTPReadTimeout() {
		return resolveDefault(RemoteJWKSet.class.getName() + ".defaultHttpReadTimeout", DEFAULT_HTTP_READ_TIMEOUT);
	}
	
	
	/**
	 * Resolves default HTTP entity size limit for JWK set retrieval, in
	 * bytes.
	 *
	 * @return The {@link #DEFAULT_HTTP_SIZE_LIMIT static constant},
	 *         overridden by setting the
	 *         {@code com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpSizeLimit}
	 *         Java system property.
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


	/**
	 * The JWK set URL.
	 */
	private final URL jwkSetURL;
	
	
	/**
	 * Optional failover JWK source.
	 */
	private final JWKSource<C> failoverJWKSource;
	

	/**
	 * The JWK set cache.
	 */
	private final JWKSetCache jwkSetCache;


	/**
	 * The JWK set retriever.
	 */
	private final ResourceRetriever jwkSetRetriever;


	/**
	 * Creates a new remote JWK set using the
	 * {@link DefaultResourceRetriever default HTTP resource retriever}
	 * with the default HTTP timeouts and entity size limit.
	 *
	 * @param jwkSetURL The JWK set URL. Must not be {@code null}.
	 */
	public RemoteJWKSet(final URL jwkSetURL) {
		this(jwkSetURL, (JWKSource<C>) null);
	}


	/**
	 * Creates a new remote JWK set using the
	 * {@link DefaultResourceRetriever default HTTP resource retriever}
	 * with the default HTTP timeouts and entity size limit.
	 *
	 * @param jwkSetURL         The JWK set URL. Must not be {@code null}.
	 * @param failoverJWKSource Optional failover JWK source in case
	 *                          retrieval from the JWK set URL fails,
	 *                          {@code null} if no failover is specified.
	 */
	public RemoteJWKSet(final URL jwkSetURL, final JWKSource<C> failoverJWKSource) {
		this(jwkSetURL, failoverJWKSource, null, null);
	}


	/**
	 * Creates a new remote JWK set.
	 *
	 * @param jwkSetURL         The JWK set URL. Must not be {@code null}.
	 * @param resourceRetriever The HTTP resource retriever to use,
	 *                          {@code null} to use the
	 *                          {@link DefaultResourceRetriever default
	 *                          one} with the default HTTP timeouts and
	 *                          entity size limit.
	 */
	public RemoteJWKSet(final URL jwkSetURL,
			    final ResourceRetriever resourceRetriever) {
		
		this(jwkSetURL, resourceRetriever, null);
	}


	/**
	 * Creates a new remote JWK set.
	 *
	 * @param jwkSetURL         The JWK set URL. Must not be {@code null}.
	 * @param resourceRetriever The HTTP resource retriever to use,
	 *                          {@code null} to use the
	 *                          {@link DefaultResourceRetriever default
	 *                          one} with the default HTTP timeouts and
	 *                          entity size limit.
	 * @param jwkSetCache       The JWK set cache to use, {@code null} to
	 *                          use the {@link DefaultJWKSetCache default
	 *                          one}.
	 */
	public RemoteJWKSet(final URL jwkSetURL,
			    final ResourceRetriever resourceRetriever,
			    final JWKSetCache jwkSetCache) {
		
		this(jwkSetURL, null, resourceRetriever, jwkSetCache);
	}


	/**
	 * Creates a new remote JWK set.
	 *
	 * @param jwkSetURL         The JWK set URL. Must not be {@code null}.
	 * @param failoverJWKSource Optional failover JWK source in case
	 *                          retrieval from the JWK set URL fails,
	 *                          {@code null} if no failover is specified.
	 * @param resourceRetriever The HTTP resource retriever to use,
	 *                          {@code null} to use the
	 *                          {@link DefaultResourceRetriever default
	 *                          one} with the default HTTP timeouts and
	 *                          entity size limit.
	 * @param jwkSetCache       The JWK set cache to use, {@code null} to
	 *                          use the {@link DefaultJWKSetCache default
	 *                          one}.
	 */
	public RemoteJWKSet(final URL jwkSetURL,
			    final JWKSource<C> failoverJWKSource,
			    final ResourceRetriever resourceRetriever,
			    final JWKSetCache jwkSetCache) {
		
		if (jwkSetURL == null) {
			throw new IllegalArgumentException("The JWK set URL must not be null");
		}
		this.jwkSetURL = jwkSetURL;
		
		this.failoverJWKSource = failoverJWKSource;

		if (resourceRetriever != null) {
			jwkSetRetriever = resourceRetriever;
		} else {
			jwkSetRetriever = new DefaultResourceRetriever(
				resolveDefaultHTTPConnectTimeout(),
				resolveDefaultHTTPReadTimeout(),
				resolveDefaultHTTPSizeLimit());
		}
		
		if (jwkSetCache != null) {
			this.jwkSetCache = jwkSetCache;
		} else {
			this.jwkSetCache = new DefaultJWKSetCache();
		}
	}


	/**
	 * Updates the cached JWK set from the configured URL.
	 *
	 * @return The updated JWK set.
	 *
	 * @throws RemoteKeySourceException If JWK retrieval failed.
	 */
	private JWKSet updateJWKSetFromURL()
		throws RemoteKeySourceException {
		Resource res;
		try {
			res = jwkSetRetriever.retrieveResource(jwkSetURL);
		} catch (IOException e) {
			throw new RemoteKeySourceException("Couldn't retrieve remote JWK set: " + e.getMessage(), e);
		}
		JWKSet jwkSet;
		try {
			jwkSet = JWKSet.parse(res.getContent());
		} catch (java.text.ParseException e) {
			throw new RemoteKeySourceException("Couldn't parse remote JWK set: " + e.getMessage(), e);
		}
		jwkSetCache.put(jwkSet);
		return jwkSet;
	}


	/**
	 * Returns the JWK set URL.
	 *
	 * @return The JWK set URL.
	 */
	public URL getJWKSetURL() {
		
		return jwkSetURL;
	}
	
	
	/**
	 * Returns the optional failover JWK source.
	 *
	 * @return The failover JWK source, {@code null} if not specified.
	 */
	public JWKSource<C> getFailoverJWKSource() {
		
		return failoverJWKSource;
	}
	
	
	/**
	 * Returns the HTTP resource retriever.
	 *
	 * @return The HTTP resource retriever.
	 */
	public ResourceRetriever getResourceRetriever() {

		return jwkSetRetriever;
	}
	
	
	/**
	 * Returns the configured JWK set cache.
	 *
	 * @return The JWK set cache.
	 */
	public JWKSetCache getJWKSetCache() {
		
		return jwkSetCache;
	}
	
	
	/**
	 * Returns the cached JWK set.
	 *
	 * @return The cached JWK set, {@code null} if none or expired.
	 */
	public JWKSet getCachedJWKSet() {
		
		return jwkSetCache.get();
	}


	/**
	 * Returns the first specified key ID (kid) for a JWK matcher.
	 *
	 * @param jwkMatcher The JWK matcher. Must not be {@code null}.
	 *
	 * @return The first key ID, {@code null} if none.
	 */
	protected static String getFirstSpecifiedKeyID(final JWKMatcher jwkMatcher) {

		Set<String> keyIDs = jwkMatcher.getKeyIDs();

		if (keyIDs == null || keyIDs.isEmpty()) {
			return null;
		}

		for (String id: keyIDs) {
			if (id != null) {
				return id;
			}
		}
		return null; // No kid in matcher
	}
	
	
	/**
	 * Fails over to the configuration optional JWK source.
	 */
	private List<JWK> failover(final Exception exception, final JWKSelector jwkSelector, final C context)
		throws RemoteKeySourceException{
		
		if (getFailoverJWKSource() == null) {
			return null;
		}
		
		try {
			return getFailoverJWKSource().get(jwkSelector, context);
		} catch (KeySourceException kse) {
			throw new RemoteKeySourceException(
				exception.getMessage() +
				"; Failover JWK source retrieval failed with: " + kse.getMessage(),
				kse
			);
		}
	}
	
	
	@Override
	public List<JWK> get(final JWKSelector jwkSelector, final C context)
		throws RemoteKeySourceException {

		// Check the cache first
		JWKSet jwkSet = jwkSetCache.get();
		
		if (jwkSetCache.requiresRefresh() || jwkSet == null) {
			// JWK set update required
			try {
				// Prevent multiple cache updates in case of concurrent requests
				// (with double-checked locking, i.e. locking on update required only)
				synchronized (this) {
					jwkSet = jwkSetCache.get();
					if (jwkSetCache.requiresRefresh() || jwkSet == null) {
						// Retrieve JWK set from URL
						jwkSet = updateJWKSetFromURL();
					}
				}
			} catch (Exception e) {
				
				List<JWK> failoverMatches = failover(e, jwkSelector, context);
				if (failoverMatches != null) {
					return failoverMatches; // Failover success
				}
				
				if (jwkSet == null) {
					// Rethrow the received exception if expired
					throw e;
				}
				
				// Continue with cached version
			}
		}

		// Run the selector on the JWK set
		List<JWK> matches = jwkSelector.select(jwkSet);

		if (! matches.isEmpty()) {
			// Success
			return matches;
		}

		// Refresh the JWK set if the sought key ID is not in the cached JWK set

		// Looking for JWK with specific ID?
		String soughtKeyID = getFirstSpecifiedKeyID(jwkSelector.getMatcher());
		if (soughtKeyID == null) {
			// No key ID specified, return no matches
			return Collections.emptyList();
		}

		if (jwkSet.getKeyByKeyId(soughtKeyID) != null) {
			// The key ID exists in the cached JWK set, matching
			// failed for some other reason, return no matches
			return Collections.emptyList();
		}
		
		try {
			// If the jwkSet in the cache is not the same instance that was
			// in the cache at the beginning of this method, then we know
			// the cache was updated
			synchronized (this) {
				if (jwkSet == jwkSetCache.get()) {
					// Make new HTTP GET to the JWK set URL
					jwkSet = updateJWKSetFromURL();
				} else {
					// Cache was updated recently, the cached value is up-to-date
					jwkSet = jwkSetCache.get();
				}
			}
		} catch (KeySourceException e) {
			
			List<JWK> failoverMatches = failover(e, jwkSelector, context);
			if (failoverMatches != null) {
				return failoverMatches; // Failover success
			}
			
			throw e;
		}
		
		
		if (jwkSet == null) {
			// Retrieval has failed
			return Collections.emptyList();
		}

		// Repeat select, return final result (success or no matches)
		return jwkSelector.select(jwkSet);
	}
}
