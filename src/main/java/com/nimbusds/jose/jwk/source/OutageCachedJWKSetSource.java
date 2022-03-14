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
import com.nimbusds.jose.proc.SecurityContext;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This JWK set source implements a workaround for temporary network problems /
 * endpoint downtime, running into minutes or hours.<br>
 * <br>
 * <p>
 * It transparently caches a delegate {@linkplain JWKSetSource}, returning the
 * cached value only when the underlying delegate throws a
 * {@linkplain JWKSetUnavailableException}.
 */

public class OutageCachedJWKSetSource<C extends SecurityContext> extends AbstractCachedJWKSetSource<C> {

	public static interface Listener<C extends SecurityContext> extends JWKSetSourceListener<C> {
		void onOutage(Exception e, long totalTimeToLive, long remainingTimeToLive, C context);
	}
	
	private final Listener<C> listener;
	
	public OutageCachedJWKSetSource(JWKSetSource<C> delegate, long duration, Listener<C> listener) {
		super(delegate, duration);
		this.listener = listener;
	}

	@Override
	public JWKSet getJWKSet(long currentTime, boolean forceUpdate, C context) throws KeySourceException {
		try {
			// cache value, if successfully refreshed by underlying source

			JWKSet all = source.getJWKSet(currentTime, forceUpdate, context);

			this.cache = createJWKSetCacheItem(all, currentTime);

			return all;
		} catch (JWKSetUnavailableException e1) {
			// attempt to get from underlying cache
			// reuse previously stored value
			if (!forceUpdate) {
				JWKSetCacheItem cache = this.cache;
				if (cache != null && cache.isValid(currentTime)) {
					long left = cache.getExpires() - currentTime; // in millis

					listener.onOutage(e1, timeToLive, left, context);

					return cache.getValue();
				}
			}

			throw e1;
		}
	}

}
