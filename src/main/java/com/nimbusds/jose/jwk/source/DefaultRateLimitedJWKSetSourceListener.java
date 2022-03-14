package com.nimbusds.jose.jwk.source;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.jose.jwk.source.RateLimitedJWKSetSource.Listener;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Default implementation which just does logging.
 * 
 * @param <C> security context
 */

public class DefaultRateLimitedJWKSetSourceListener<C extends SecurityContext> extends AbstractJWKSetSourceListener implements Listener<C> {

	public DefaultRateLimitedJWKSetSourceListener(Level level) {
		this(Logger.getLogger(DefaultRateLimitedJWKSetSourceListener.class.getName()), level);
	}
	
	public DefaultRateLimitedJWKSetSourceListener(Logger logger, Level level) {
		super(level, logger);
	}
	
	@Override
	public void onRateLimited(long duration, long remaining, C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "Rate-limit for loading JWKs exceeded, next opportunity in " + remaining + " ms");
		}
	}
	
}