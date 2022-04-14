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

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;


/**
 * {@linkplain JWKSetSource} that limits the number of requests in a time
 * period. Intended to guard against frequent, potentially costly, downstream
 * calls.
 *
 * <b>Two invocations per time period are allowed, so that, under normal
 * operation, there is always one invocation left in case the keys are rotated
 * and this results in triggering a refresh of the JWK set. The other request
 * is (sometimes) consumed by background refreshes.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-09
 */
@ThreadSafe
public class RateLimitedJWKSetSource<C extends SecurityContext> extends JWKSetSourceWrapper<C> {

	public interface Listener<C extends SecurityContext> extends JWKSetSourceListener<C> {
		void onRateLimited(final long duration, final long remaining, final C context);
	}
	
	private final long minTimeInterval;
	private long nextOpeningTime = -1L;
	private int counter = 0;
	private final Listener<C> listener;

	
	/**
	 * Creates a new JWK set source that limits the number of requests.
	 *
	 * @param source          The JWK set source to decorate. Must not be
	 *                        {@code null}.
	 * @param minTimeInterval The minimum allowed time interval between two
	 *                        JWK set retrievals, in milliseconds.
	 * @param listener        The listener, {@code null} if not specified.
	 */
	public RateLimitedJWKSetSource(final JWKSetSource<C> source, final long minTimeInterval, final Listener<C> listener) {
		super(source);
		this.minTimeInterval = minTimeInterval;
		this.listener = listener;
	}
	
	
	@Override
	public JWKSet getJWKSet(final boolean forceReload, final long currentTime, final C context)
		throws KeySourceException {
		
		// implementation note: this code is not intended to run many parallel threads
		// for the same instance, thus use of synchronized will not cause congestion
		
		boolean rateLimitHit;
		synchronized (this) {
			if (nextOpeningTime <= currentTime) {
				nextOpeningTime = currentTime + minTimeInterval;
				counter = 1;
				rateLimitHit = false;
			} else {
				rateLimitHit = counter <= 0;
				if (! rateLimitHit) {
					counter--;
				}
			}
		}
		if (rateLimitHit) {
			listener.onRateLimited(minTimeInterval, nextOpeningTime - currentTime, context);
			throw new RateLimitReachedException();
		}
		return getSource().getJWKSet(forceReload, currentTime, context);
	}
}
