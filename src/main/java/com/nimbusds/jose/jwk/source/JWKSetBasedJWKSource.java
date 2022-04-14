/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
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


import java.io.Closeable;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthStatusReporting;


/**
 * JSON Web Key (JWK) set based JWK source.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-09
 */
@ThreadSafe
public class JWKSetBasedJWKSource<C extends SecurityContext> implements JWKSource<C>, Closeable, HealthStatusReporting<C> {

	
	private final JWKSetSource<C> source;
	
	
	/**
	 * Creates a new JWK set based JWK source.
	 *
	 * @param source The JWK set source. Must not be {@code null}.
	 */
	public JWKSetBasedJWKSource(final JWKSetSource<C> source) {
		Objects.requireNonNull(source);
		this.source = source;
	}

	@Override
	public List<JWK> get(final JWKSelector jwkSelector, final C context) throws KeySourceException {
		
		long currentTime = System.currentTimeMillis();
		
		// Get the list of JWKs and match against the selector
		// if no matches, attempt to refresh the list of JWKs
		// and rerun matching. 
		
		// So for the no-match scenario, what we really have is a
		// read-write-read type transaction. In order to identify
		// whether another thread has already performed the write operation,
		// the timestamp for the original read operation is passed along
		// and used internally to check whether the cache is up to date; preventing
		// unnecessary external calls
		
		List<JWK> select = jwkSelector.select(source.getJWKSet(false, currentTime, context));
		if (select.isEmpty()) {
			select = jwkSelector.select(source.getJWKSet(true, currentTime, context));
		}
		return select;
	}
	
	
	/**
	 * Returns the underlying JWK set source.
	 *
	 * @return The JWK set source.
	 */
	public JWKSetSource<C> getSource() {
		return source;
	}
	
	
	@Override
	public void close() throws IOException {
		source.close();
	}
	
	
	@Override
	public HealthReport reportHealthStatus(final boolean refresh, C context) {
		return source.reportHealthStatus(refresh, context);
	}
}
