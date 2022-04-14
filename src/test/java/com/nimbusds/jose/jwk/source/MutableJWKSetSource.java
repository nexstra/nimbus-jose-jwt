package com.nimbusds.jose.jwk.source;

import java.io.IOException;
import java.util.Objects;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthStatus;


public class MutableJWKSetSource<C extends SecurityContext> implements JWKSetSource<C> {

	private JWKSet jwkSet;

	@Override
	public HealthReport reportHealthStatus(boolean refresh, C context) {
		return new HealthReport(HealthStatus.NOT_SUPPORTED);
	}

	@Override
	public void close() throws IOException {
		// do nothing
	}

	@Override
	public JWKSet getJWKSet(final boolean forceReload, final long currentTime, final C context) throws KeySourceException {
		return jwkSet;
	}

	public void setJwkSet(final JWKSet jwkSet) {
		Objects.requireNonNull(jwkSet);
		this.jwkSet = jwkSet;
	}
}
