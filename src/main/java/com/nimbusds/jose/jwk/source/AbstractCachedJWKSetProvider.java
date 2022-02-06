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
 * Jwk provider that caches previously obtained list of Jwk in memory.
 */

public abstract class AbstractCachedJWKSetProvider extends BaseJWKSetProvider {

	protected static class JWKSetCacheItem {

		// must be final so that initialization is safe
		// https://shipilev.net/blog/2014/safe-public-construction/
		private final JWKSet value;
		private final long expires;

		public JWKSetCacheItem(JWKSet value, long expires) {
			this.value = value;
			this.expires = expires;
		}

		public boolean isValid(long time) {
			return time <= expires;
		}

		public JWKSet getValue() {
			return value;
		}

		public long getExpires() {
			return expires;
		}

	}

	protected volatile JWKSetCacheItem cache;
	protected final long timeToLive; // milliseconds

	public AbstractCachedJWKSetProvider(JWKSetProvider provider, long timeToLive) {
		super(provider);
		this.timeToLive = timeToLive;
	}

	abstract JWKSet getJWKSet(long time, boolean forceUpdate) throws KeySourceException;

	long getExpires(long time) {
		return time + timeToLive;
	}

	long getTimeToLive() {
		return timeToLive;
	}

	@Override
	public JWKSet getJWKSet(boolean forceUpdate) throws KeySourceException {
		return getJWKSet(System.currentTimeMillis(), forceUpdate);
	}

	protected JWKSetCacheItem getCache(long time) {
		JWKSetCacheItem threadSafeCache = this.cache; // defensive copy
		if (threadSafeCache != null && threadSafeCache.isValid(time)) {
			return threadSafeCache;
		}
		return null;
	}
}
