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


import java.util.Date;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.jwk.JWKSet;


/**
 * JSON Web Key (JWK) set with timestamp.
 *
 * @author Vladimir Dzhuvinov
 * @version 2020-12-27
 * @deprecated see {@linkplain RemoteJWKSet}.
 */
@Deprecated
@Immutable
public final class JWKSetWithTimestamp {


	private final JWKSet jwkSet;
	
	
	private final Date timestamp;
	
	
	/**
	 * Creates a new JWK set with a timestamp set to now.
	 */
	public JWKSetWithTimestamp(final JWKSet jwkSet) {
		this(jwkSet, new Date());
	}
	
	
	/**
	 * Creates a new JWK set with timestamp.
	 *
	 * @param jwkSet    The JWK set. Must not be {@code null}.
	 * @param timestamp The timestamp date. Must not be {@code null}.
	 */
	public JWKSetWithTimestamp(final JWKSet jwkSet, final Date timestamp) {
		if (jwkSet == null) {
			throw new IllegalArgumentException("The JWK set must not be null");
		}
		this.jwkSet = jwkSet;
		if (timestamp == null) {
			throw new IllegalArgumentException("The timestamp must not null");
		}
		this.timestamp = timestamp;
	}
	
	
	/**
	 * Returns the JWK set.
	 *
	 * @return The JWK set.
	 */
	public JWKSet getJWKSet() {
		return jwkSet;
	}
	
	
	/**
	 * Returns the timestamp date.
	 *
	 * @return The timestamp date.
	 */
	public Date getDate() {
		return timestamp;
	}
}
