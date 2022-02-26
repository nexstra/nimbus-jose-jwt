package com.nimbusds.jose.jwk.source;

import java.util.logging.Level;
import java.util.logging.Logger;

import com.nimbusds.jose.jwk.source.OutageCachedJWKSetSource.Listener;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Default implementation which just does logging.
 * 
 * @param <C> security context
 */

public class DefaultOutageCachedJWKSetSourceListener<C extends SecurityContext> extends AbstractJWKSetSourceListener implements Listener<C> {

	private final Level escalationLevel;

	public DefaultOutageCachedJWKSetSourceListener(Level level, Level escalationLevel) {
		this(Logger.getLogger(DefaultOutageCachedJWKSetSourceListener.class.getName()), level, escalationLevel);
	}
	
	public DefaultOutageCachedJWKSetSourceListener(Logger logger, Level level, Level escalationLevel) {
		super(level, logger);
		this.escalationLevel = escalationLevel;
	}
	
	@Override
	public void onOutage(Exception e, long totalTimeToLive, long remainingTimeToLive, C context) {
		
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

		Level l;
		if (percent < 50 || minutes < 30) {
			l = escalationLevel;
		} else {
			l = level;
		}
		
		if(logger.isLoggable(level)) {
			String message = "Unable to refresh keys for verification of Json Web Token signatures. Verification will stop as outage cache expires in "
					+ hours + " hours and " + minutes + " minutes.";
	
			logger.log(level, message, e);
		}
	}
	
}