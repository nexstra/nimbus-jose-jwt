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

import com.nimbusds.jose.jwk.source.CachingJWKSetSource.Listener;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Logs {@linkplain com.nimbusds.jose.jwk.source.CachingJWKSetSource} events.
 */
public class CachingJWKSetSourceLogger<C extends SecurityContext> extends AbstractJWKSetSourceListener implements Listener<C> {

	
	public CachingJWKSetSourceLogger(final Level level) {
		this(Logger.getLogger(CachingJWKSetSourceLogger.class.getName()), level);
	}
	
	
	public CachingJWKSetSourceLogger(final Logger logger, final Level level) {
		super(level, logger);
	}

	
	@Override
	public void onPendingCacheRefresh(final int queueLength, final C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "Perform JWK cache refresh..");
		}
	}

	
	@Override
	public void onCacheRefreshed(final int jwksCount, final int queueLength, final C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "JWK cache refreshed (with " + queueLength + " waiting), now have " + jwksCount + " JWKs");
		}
	}

	
	@Override
	public void onWaitingForCacheRefresh(final long timeout, final int queueLength, final C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "Wait for up to " + timeout + "ms for the JWK cache to be refreshed (with " + queueLength + " already waiting)");
		}
	}

	
	@Override
	public void onUnableToRefreshCache(final C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "Unable to refresh cache");
		}
	}

	
	@Override
	public void onTimeoutWaitingForCacheRefresh(final long timeout, final int queueLength, final C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "Waited for " + timeout + "ms for the JWK cache to be refreshed (with " + queueLength + " already waiting), giving up.");
		}
	}
}