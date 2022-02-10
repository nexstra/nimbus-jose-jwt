package com.nimbusds.jose.jwk.source;

import java.io.IOException;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;

public class MutableJWKSetProvider implements JWKSetProvider {

	private JWKSet set;
	
	@Override
	public JWKSetHealth getHealth(boolean refresh) {
		throw new JWKSetHealthNotSupportedException("Provider " + getClass().getName() + " does not support health requests");
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
	public JWKSet getJWKSet(long time, boolean forceUpdate) throws KeySourceException {
		return set;
	}

	public void setSet(JWKSet set) {
		this.set = set;
	}
}
