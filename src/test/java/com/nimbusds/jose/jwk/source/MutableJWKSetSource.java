package com.nimbusds.jose.jwk.source;

import java.io.IOException;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;

public class MutableJWKSetSource<C extends SecurityContext> implements JWKSetSource<C> {

	private JWKSet set;
	
	@Override
	public JWKSetHealth getHealth(boolean refresh, C context) {
		throw new UnsupportedOperationException(getClass().getName() + " does not support health requests");
	}

	@Override
	public boolean supportsHealth() {
		return false;
	}

	@Override
	public void close() throws IOException {
		// do nothing
	}

	@Override
	public JWKSet getJWKSet(long time, boolean forceUpdate, C context) throws KeySourceException {
		return set;
	}

	public void setSet(JWKSet set) {
		this.set = set;
	}
}
