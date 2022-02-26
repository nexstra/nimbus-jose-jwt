package com.nimbusds.jose.jwk.source;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.jose.jwk.source.PreemptiveCachedJWKSetSource.Listener;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Default implementation which just does logging.
 * 
 * @param <C> security context
 */

public class DefaultPreemptiveCachedJWKSetSourceListener<C extends SecurityContext> extends DefaultCachedJWKSetSourceListener<C> implements Listener<C> {

	public DefaultPreemptiveCachedJWKSetSourceListener(Level level) {
		this(Logger.getLogger(DefaultPreemptiveCachedJWKSetSourceListener.class.getName()), level);
	}
	
	public DefaultPreemptiveCachedJWKSetSourceListener(Logger logger, Level level) {
		super(logger, level);
	}
	
	@Override
	public void onEagerCacheRefreshScheduled(long time, C context) {
		logger.log(level, "Scheduled next eager JWKs refresh in " + (time/1000) + " seconds");
	}

	@Override
	public void onEagerCacheRefreshNotScheduled(C context) {
		logger.log(level, "Not scheduling eager JWKs refresh");
	}

	@Override
	public void onEagerCacheRefreshFailed(Exception e, C context) {
		logger.log(level, "Scheduled eager JWKs refresh failed", e);
	}

	@Override
	public void onPendingPreemptiveCacheRefresh(C context) {
		logger.log(level, "Perform preemptive JWKs refresh..");
	}

	@Override
	public void onPreemptiveCacheRefreshed(C context) {
		logger.log(level, "Cache preemptively refreshed");
	}

	@Override
	public void onUnableToPreemptiveRefreshCache(C context) {
		logger.log(level, "Unable to preemptively refresh JWKs");
	}

	
}