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

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This provider implements a workaround for transient network problems. <br>
 * <br>
 * It retries getting the list of Jwks if the wrapped provider throws a
 * {@linkplain JWKSetUnavailableException}.
 */

public class RetryingJWKSetProvider extends BaseJWKSetProvider {

	private static final Logger LOGGER = Logger.getLogger(RetryingJWKSetProvider.class.getName());

	public RetryingJWKSetProvider(JWKSetProvider provider) {
		super(provider);
	}

	@Override
	public JWKSet getJWKSet(boolean forceUpdate) throws KeySourceException {
		try {
			return provider.getJWKSet(forceUpdate);
		} catch (JWKSetUnavailableException e) {
			// assume transient network issue, retry once
			LOGGER.log(Level.WARNING, "Received exception getting JWKs, retrying once", e);

			return provider.getJWKSet(forceUpdate);
		}
	}

}
