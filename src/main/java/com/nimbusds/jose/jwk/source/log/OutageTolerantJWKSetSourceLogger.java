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

import com.nimbusds.jose.jwk.source.OutageTolerantJWKSetSource.Listener;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Logs {@linkplain com.nimbusds.jose.jwk.source.OutageTolerantJWKSetSource}
 * events.
 */
public class OutageTolerantJWKSetSourceLogger<C extends SecurityContext> extends AbstractJWKSetSourceListener implements Listener<C> {

	
	private final Level escalationLevel;

	
	public OutageTolerantJWKSetSourceLogger(final Level level, final Level escalationLevel) {
		this(Logger.getLogger(OutageTolerantJWKSetSourceLogger.class.getName()), level, escalationLevel);
	}
	
	
	public OutageTolerantJWKSetSourceLogger(final Logger logger, final Level level, final Level escalationLevel) {
		super(level, logger);
		this.escalationLevel = escalationLevel;
	}
	
	
	@Override
	public void onOutage(final Exception e, final long totalTimeToLive, final long remainingTimeToLive, final C context) {
		
		// So validation of tokens will still work, but fail as soon as this cache
		// expires.
		// Note that issuing new tokens will probably not work when this operation does
		// not work either.
		//
		// Logging scheme:
		// 50% time left, or less than one hour -> error
		// 50-100% time left -> warning

		long minutes = (remainingTimeToLive % 3600000) / 60000;
		long hours = remainingTimeToLive / 3600000;

		long percent = (remainingTimeToLive * 100) / totalTimeToLive;

		Level l; // TODO var not used?
		if (percent < 50 || minutes < 30) {
			l = escalationLevel;
		} else {
			l = level;
		}
		
		if(logger.isLoggable(level)) {
			// TODO edit message, not in context
			String message = "Unable to refresh keys for verification of Json Web Token signatures. Verification will stop as outage cache expires in "
					+ hours + " hours and " + minutes + " minutes.";
	
			logger.log(level, message, e);
		}
	}
}