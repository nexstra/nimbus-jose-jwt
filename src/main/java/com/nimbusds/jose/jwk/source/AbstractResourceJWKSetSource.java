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

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;

import java.io.IOException;
import java.net.URL;

/**
 * Abstract superclass for {@linkplain JWKSetSource} getting its data from an URL.
 */

public abstract class AbstractResourceJWKSetSource<C extends SecurityContext> implements JWKSetSource<C> {

	protected final URL url;

	/**
	 * Creates a set source that loads from the given URL.
	 *
	 * @param url			   The URL of the JWKs
	 * @param resourceRetriever Resource retriever
	 */
	public AbstractResourceJWKSetSource(URL url) {
		checkArgument(url != null, "A non-null url is required");

		this.url = url;
	}

	protected void checkArgument(boolean valid, String message) {
		if (!valid) {
			throw new IllegalArgumentException(message);
		}
	}

	public JWKSet getJWKSet(long currentTime, boolean forceUpdate, C context) throws KeySourceException {
		Resource res = getResource(context);
		try {
			// Note on error handling: We want to avoid any generic HTML document 
			// (i.e. default HTTP error pages) and other invalid responses being accepted 
			// as an empty list of JWKs. This is handled by the underlying parser; 
			// it checks that the transferred document is in fact a JSON document, 
			// and that the "keys" field is present.
			
			return JWKSet.parse(res.getContent());
		} catch (Exception e) {
			// assume the server returns some kind of generic or incomplete document, 
			// treat this equivalent to an input/output exception.

			throw new JWKSetParseException("Unable to parse JWKs", e);
		}
	}

	@Override
	public void close() throws IOException {
		// do nothing
	}

	public JWKSetHealth getHealth(boolean refresh, C context) {
		throw new UnsupportedOperationException(getClass().getName() + " does not support health requests");
	}

	@Override
	public boolean supportsHealth() {
		return false;
	}

	protected abstract Resource getResource(C context) throws JWKSetTransferException;


}