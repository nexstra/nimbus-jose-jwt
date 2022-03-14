package com.nimbusds.jose.jwk.source;

import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class AbstractJWKSetSourceListener {

	protected final Level level;
	protected final Logger logger;

	public AbstractJWKSetSourceListener(Level level, Logger logger) {
		this.level = level;
		this.logger = logger;
	}
	
}
