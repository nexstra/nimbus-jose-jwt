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


import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.proc.SecurityContext;
import net.jcip.annotations.ThreadSafe;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;


/**
 * JSON Web Key (JWK) source. 
 */
@ThreadSafe
public class UrlJWKSource<C extends SecurityContext> implements JWKSource<C>, Closeable, JWKSetHealthProvider {

	private final JWKSetProvider provider;

	public UrlJWKSource(JWKSetProvider provider) {
		super();
		this.provider = provider;
	}

	@Override
	public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {
		return get(jwkSelector, System.currentTimeMillis(), context);
	}

	public List<JWK> get(JWKSelector jwkSelector, long time, C context) throws KeySourceException {
		
		// Get the list of JWKs and match against the selector
		// if no matches, attempt to refresh the list of JWKs
		// and rerun matching. 
		
		// So for the no-match scenario, what we really have is a
		// read-write-read type transaction. In order to identify
		// whether another thread has already performed the write operation,
		// the timestamp for the original read operation is passed along
		// and used internally to check whether the cache is up to date; preventing
		// unnecessary external calls
		
		List<JWK> select = jwkSelector.select(provider.getJWKSet(time, false));
		if (select.isEmpty()) {
			select = jwkSelector.select(provider.getJWKSet(time, true));
		}
		return select;
	}

	@Override
	public void close() throws IOException {
		provider.close();
	}

	@Override
	public JWKSetHealth getHealth(boolean refresh) {
		return provider.getHealth(refresh);
	}

	@Override
	public boolean supportsHealth() {
		return provider.supportsHealth();
	}

	// for testing
	JWKSetProvider getProvider() {
		return provider;
	}

}
