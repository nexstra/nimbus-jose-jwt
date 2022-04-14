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

package com.nimbusds.jose.jwk.source.log;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource.Listener;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Logs {@linkplain com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource}
 * events.
 */
public class RefreshAheadCachingJWKSetSourceLogger<C extends SecurityContext> extends CachingJWKSetSourceLogger<C> implements Listener<C> {

	
	public RefreshAheadCachingJWKSetSourceLogger(final Level level) {
		this(Logger.getLogger(RefreshAheadCachingJWKSetSourceLogger.class.getName()), level);
	}
	
	
	public RefreshAheadCachingJWKSetSourceLogger(final Logger logger, final Level level) {
		super(logger, level);
	}
	
	
	@Override
	public void onCacheRefreshScheduled(final long time, final C context) {
		logger.log(level, "Scheduled next eager JWKs refresh in " + (time/1000) + " seconds");
	}

	@Override
	public void onCacheRefreshNotScheduled(final C context) {
		logger.log(level, "Not scheduling eager JWKs refresh");
	}
	

	@Override
	public void onScheduledCacheRefreshFailed(final Exception e, final C context) {
		logger.log(level, "Scheduled eager JWKs refresh failed", e);
	}

	
	@Override
	public void onInitiatedCacheRefreshAheadOfExpiration(final C context) {
		logger.log(level, "Perform preemptive JWKs refresh..");
	}

	
	@Override
	public void onCacheRefreshedAheadOfExpiration(final C context) {
		logger.log(level, "Cache refreshed ahead of expiration");
	}

	
	@Override
	public void onUnableToRefreshCacheAheadOfExpiration(final C context) {
		logger.log(level, "Unable to refresh JWK set");
	}
}