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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * JWK set source that caches previously obtained list of JWK in memory.
 */

public abstract class AbstractCachedJWKSetSource<C extends SecurityContext> extends BaseJWKSetSource<C> {

	protected static class JWKSetCacheItem {

		// must be final so that initialization is safe
		// https://shipilev.net/blog/2014/safe-public-construction/
		private final JWKSet value;
		private final long expires;
		private final long timestamp;
		
		public JWKSetCacheItem(JWKSet value, long timestamp, long expires) {
			this.value = value;
			this.timestamp = timestamp;
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
		
		public long getTimestamp() {
			return timestamp;
		}

	}

	protected volatile JWKSetCacheItem cache;
	protected final long timeToLive; // milliseconds

	public AbstractCachedJWKSetSource(JWKSetSource<C> source, long timeToLive) {
		super(source);
		this.timeToLive = timeToLive;
	}

	long getExpires(long time) {
		return time + timeToLive;
	}

	long getTimeToLive() {
		return timeToLive;
	}

	protected JWKSetCacheItem getCache(long time) {
		JWKSetCacheItem threadSafeCache = this.cache; // defensive copy
		if (threadSafeCache != null && threadSafeCache.isValid(time)) {
			return threadSafeCache;
		}
		return null;
	}
	
	protected JWKSetCacheItem createJWKSetCacheItem(JWKSet all, long requestTime) {
		// save to cache
		// Set a new timestamp, so that threads which did a 
		// read-then-force-refresh move can identify that the keys were in 
		// fact updated if multiple threads wanted to force refresh at the same time
		long timestamp = currentTimeMillis();
		
		return new JWKSetCacheItem(all, timestamp, getExpires(requestTime));
	}
	
	protected long currentTimeMillis() {
		return System.currentTimeMillis();
	}

}
