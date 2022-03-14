package com.nimbusds.jose.jwk.source;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.jose.jwk.source.CachedJWKSetSource.Listener;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Default implementation which just does logging.
 * 
 * @param <C> security context
 */

public class DefaultCachedJWKSetSourceListener<C extends SecurityContext> extends AbstractJWKSetSourceListener implements Listener<C> {

	public DefaultCachedJWKSetSourceListener(Level level) {
		this(Logger.getLogger(DefaultCachedJWKSetSourceListener.class.getName()), level);
	}
	
	public DefaultCachedJWKSetSourceListener(Logger logger, Level level) {
		super(level, logger);
	}

	@Override
	public void onPendingCacheRefresh(int queueLength, C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "Perform JWK cache refresh..");
		}
	}

	@Override
	public void onCacheRefreshed(int jwksCount, int queueLength, C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "JWK cache refreshed (with " + queueLength + " waiting), now have " + jwksCount + " JWKs");
		}
	}

	@Override
	public void onWaitingForCacheRefresh(long timeout, int queueLength, C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "Wait for up to " + timeout + "ms for the JWK cache to be refreshed (with " + queueLength + " already waiting)");
		}
	}

	@Override
	public void onUnableToRefreshCache(C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "Unable to refresh cache");
		}
	}

	@Override
	public void onTimeoutWaitingForCacheRefresh(long timeout, int queueLength, C context) {
		if(logger.isLoggable(level)) {
			logger.log(level, "Waited for " + timeout + "ms for the JWK cache to be refreshed (with " + queueLength + " already waiting), giving up.");
		}
	}
	
}