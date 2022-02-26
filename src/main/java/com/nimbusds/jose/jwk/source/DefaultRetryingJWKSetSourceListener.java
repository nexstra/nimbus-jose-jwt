package com.nimbusds.jose.jwk.source;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.jose.jwk.source.RetryingJWKSetSource.Listener;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Default implementation which just does logging.
 * 
 * @param <C> security context
 */

public class DefaultRetryingJWKSetSourceListener<C extends SecurityContext> extends AbstractJWKSetSourceListener implements Listener<C> {

	public DefaultRetryingJWKSetSourceListener(Level level) {
		this(Logger.getLogger(DefaultRetryingJWKSetSourceListener.class.getName()), level);
	}
	
	public DefaultRetryingJWKSetSourceListener(Logger logger, Level level) {
		super(level, logger);
	}

	@Override
	public void onRetrying(Exception e, C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "Received exception getting JWKs, retrying once", e);
		}
	}
	
}