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

import com.nimbusds.jose.jwk.source.RateLimitedJWKSetSource.Listener;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Logs {@linkplain com.nimbusds.jose.jwk.source.RateLimitedJWKSetSource}
 * events.
 */
public class RateLimitedJWKSetSourceLogger<C extends SecurityContext> extends AbstractJWKSetSourceListener implements Listener<C> {

	
	public RateLimitedJWKSetSourceLogger(final Level level) {
		this(Logger.getLogger(RateLimitedJWKSetSourceLogger.class.getName()), level);
	}
	
	
	public RateLimitedJWKSetSourceLogger(final Logger logger, final Level level) {
		super(level, logger);
	}
	
	
	@Override
	public void onRateLimited(final long duration, final long remaining, final C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "Rate-limit for loading JWKs exceeded, next opportunity in " + remaining + " ms");
		}
	}
	
}