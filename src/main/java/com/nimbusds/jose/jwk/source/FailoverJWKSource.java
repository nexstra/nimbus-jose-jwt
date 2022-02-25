/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2022, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.jwk.source;


import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.IOUtils;

import net.jcip.annotations.ThreadSafe;

import java.io.Closeable;
import java.util.List;

@ThreadSafe
public class FailoverJWKSource<C extends SecurityContext> implements JWKSource<C>, JWKSetHealthSource, Closeable {

	private final JWKSource<C> failoverJWKSource;
	private final JWKSource<C> jwkSource;

	private final JWKSetHealthSource jwkSourcehHealthSource;
	private final JWKSetHealthSource failoverJWKSourcehHealthSource;

	/**
	 * Creates a new remote JWK set using a failover.
	 *
	 * @param failoverJWKSource Optional failover JWK source in case
	 *						  retrieval from the JWK set URL fails,
	 *						  {@code null} if no failover is specified.
	 */
	public FailoverJWKSource(final JWKSource<C> jwkSource, final JWKSource<C> failoverJWKSource) {
		this.jwkSource = jwkSource;
		this.failoverJWKSource = failoverJWKSource;

		if (supportsHealth(jwkSource)) {
			jwkSourcehHealthSource = (JWKSetHealthSource) jwkSource;
		} else {
			jwkSourcehHealthSource = null;
		}

		if (supportsHealth(failoverJWKSource)) {
			failoverJWKSourcehHealthSource = (JWKSetHealthSource) failoverJWKSource;
		} else {
			failoverJWKSourcehHealthSource = null;
		}

	}

	private boolean supportsHealth(JWKSource<C> source) {
		if (source instanceof JWKSetHealthSource) {
			JWKSetHealthSource jwkSetHealthSource = (JWKSetHealthSource) source;
			return jwkSetHealthSource.supportsHealth();
		}
		return false;
	}

	/**
	 * Fails over to the configuration optional JWK source.
	 */
	private List<JWK> failover(final Exception exception, final JWKSelector jwkSelector, final C context)
			throws RemoteKeySourceException {

		try {
			return failoverJWKSource.get(jwkSelector, context);
		} catch (KeySourceException kse) {
			throw new RemoteKeySourceException(
					exception.getMessage() +
							"; Failover JWK source retrieval failed with: " + kse.getMessage(),
					kse
			);
		}
	}

	@Override
	public List<JWK> get(final JWKSelector jwkSelector, final C context)
			throws RemoteKeySourceException {
		// JWK set update required
		try {
			return jwkSource.get(jwkSelector, context);
		} catch (Exception e) {
			return failover(e, jwkSelector, context);
		}
	}

	@Override
	public void close() {
		if(jwkSource instanceof Closeable) {
			IOUtils.closeSilently((Closeable)jwkSource);
		}
		if(failoverJWKSource instanceof Closeable) {
			IOUtils.closeSilently((Closeable)failoverJWKSource);
		}
	}


	@Override
	public JWKSetHealth getHealth(boolean refresh) {
		JWKSetHealth health = null;
		if (jwkSourcehHealthSource != null) {
			health = jwkSourcehHealthSource.getHealth(refresh);
		}
		if (health == null || !health.isSuccess()) {
			if (failoverJWKSourcehHealthSource != null) {
				health = failoverJWKSourcehHealthSource.getHealth(refresh);
			}
		}
		if (health == null) {
			throw new JWKSetHealthNotSupportedException("Health requests not supported");
		}
		return null;
	}

	@Override
	public boolean supportsHealth() {
		return jwkSourcehHealthSource != null || failoverJWKSourcehHealthSource != null;
	}
}
