/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2022, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.jwk.source;

import java.io.IOException;
import java.util.Objects;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.health.HealthReport;


/**
 * Wraps a {@linkplain JWKSetSource} to provide convenient decoration be means
 * of subclassing. Implements the Wrapper or Decorator pattern.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-09
 */
public abstract class JWKSetSourceWrapper<C extends SecurityContext> implements JWKSetSource<C> {
	
	
	/**
	 * The wrapped JWK set source.
	 */
	private final JWKSetSource<C> source;
	
	
	/**
	 * Creates a new JWK set wrapper.
	 *
	 * @param source The JWK set source to wrap. Must not be {@code null}.
	 */
	public JWKSetSourceWrapper(final JWKSetSource<C> source) {
		Objects.requireNonNull(source);
		this.source = source;
	}
	
	
	/**
	 * Returns the wrapped JWK set source.
	 *
	 * @return The wrapped Jwk set source.
	 */
	public JWKSetSource<C> getSource() {
		return source;
	}
	
	
	@Override
	public void close() throws IOException {
		source.close();
	}

	
	@Override
	public HealthReport reportHealthStatus(final boolean refresh, final C context) {
		return source.reportHealthStatus(refresh, context);
	}
}
