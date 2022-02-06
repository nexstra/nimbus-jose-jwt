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


/**
 * 
 * {@linkplain JWKSetProvider} that limits the number of invocations per time
 * unit. This guards against frequent, potentially costly, downstream calls.
 * 
 */

public class RateLimitedJWKSetProvider extends BaseJWKSetProvider {

	private final long millisecondsPerRequest;
	private long nextLimit = -1L;

	/**
	 * Creates a new provider that throttles the number of requests for a JWKSet.
	 *
	 * @param millisecondsPerRequest minimum number of milliseconds per downstream request.
	 * @param provider			   provider to use to request jwk when the bucket allows it.
	 */
	public RateLimitedJWKSetProvider(JWKSetProvider provider, long millisecondsPerRequest) {
		super(provider);
		this.millisecondsPerRequest = millisecondsPerRequest;
	}

	@Override
	public JWKSet getJWKSet(boolean forceUpdate) throws KeySourceException {
		return getJWKSet(forceUpdate, System.currentTimeMillis());
	}

	public JWKSet getJWKSet(boolean forceUpdate, long time) throws KeySourceException {
		if (nextLimit > time) {
			throw new RateLimitReachedException();
		}
		synchronized (this) {
			if (nextLimit > time) {
				throw new RateLimitReachedException();
			}
			nextLimit = time + millisecondsPerRequest;
		}

		return provider.getJWKSet(forceUpdate);
	}

}
