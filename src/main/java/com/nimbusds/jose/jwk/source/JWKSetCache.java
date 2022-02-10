/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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


import com.nimbusds.jose.jwk.JWKSet;


/**
 * JSON Web Key (JWK) set cache. Implementations should be thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @author Sarvesh Sharma
 * @version 2020-03-11
 * @deprecated see {@linkplain RemoteJWKSet}.
 */
@Deprecated
public interface JWKSetCache {
	
	
	/**
	 * Puts the specified JWK set into the cache or clears the cache.
	 *
	 * @param jwkSet The JWK set to cache, {@code null} to clear the cache.
	 */
	void put(final JWKSet jwkSet);
	
	
	/**
	 * Gets the cached JWK set.
	 *
	 * @return The cached JWK set, {@code null} if none or expired.
	 */
	JWKSet get();


	/**
	 * Returns {@code true} if the cached JWK set requires a refresh. This
	 * should typically occur some time before the cache has expired, to
	 * allow for transient retrieval exceptions before expiration.
	 *
	 * @return {@code true} if the cached JWK set requires a refresh.
	 */
	boolean requiresRefresh();
}
