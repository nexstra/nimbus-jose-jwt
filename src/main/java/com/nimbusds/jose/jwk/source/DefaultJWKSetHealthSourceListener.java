package com.nimbusds.jose.jwk.source;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.jose.proc.SecurityContext;

/**
 * Default implementation which just does logging.
 * 
 * @param <C> security context
 */

public class DefaultJWKSetHealthSourceListener<C extends SecurityContext> extends AbstractJWKSetSourceListener implements JWKSetHealthSourceListener<C> {

	public DefaultJWKSetHealthSourceListener(Level level) {
		super(level, Logger.getLogger(DefaultJWKSetHealthSourceListener.class.getName()));
	}
	
	public DefaultJWKSetHealthSourceListener(Logger logger, Level level) {
		super(level, logger);
	}

	@Override
	public void onHealthRefreshException(Exception e, C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "Exception refreshing health status.", e);
		}
	}

}
