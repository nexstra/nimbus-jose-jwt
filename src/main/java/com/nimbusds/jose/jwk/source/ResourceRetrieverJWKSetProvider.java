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
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;

import java.io.IOException;
import java.net.URL;
import java.util.logging.Logger;

/**
 * Jwk provider that loads them from a {@link URL}
 */

public class ResourceRetrieverJWKSetProvider implements JWKSetProvider {

	private static final Logger LOGGER = Logger.getLogger(ResourceRetrieverJWKSetProvider.class.getName());

	private final URL url;
	private final ResourceRetriever resourceRetriever;

	/**
	 * Creates a provider that loads from the given URL
	 *
	 * @param url			   The url of the JWKs
	 * @param resourceRetriever ResourceRetriever
	 */
	public ResourceRetrieverJWKSetProvider(URL url, ResourceRetriever resourceRetriever) {
		checkArgument(url != null, "A non-null url is required");
		checkArgument(resourceRetriever != null, "A non-null ResourceRetriever is required");

		this.url = url;
		this.resourceRetriever = resourceRetriever;
	}

	protected void checkArgument(boolean valid, String message) {
		if (!valid) {
			throw new IllegalArgumentException(message);
		}
	}

	public JWKSet getJWKSet(boolean forceUpdate) throws KeySourceException {
		LOGGER.info("Requesting JWKs from " + url + "..");

		Resource res;
		try {
			res = resourceRetriever.retrieveResource(url);
		} catch (IOException e) {
			throw new RemoteKeySourceException("Couldn't retrieve remote JWK set: " + e.getMessage(), e);
		}
		try {
			JWKSet jwkSet = JWKSet.parse(res.getContent());

			if (jwkSet == null || jwkSet.isEmpty()) {
				// assume the server returns some kind of incomplete document, treat this
				// equivalent to an input/output exception.
				throw new RemoteKeySourceException("No JWKs found at " + url);
			}
			LOGGER.info(url + " returned " + jwkSet.size() + " JWKs");

			return jwkSet;
		} catch (java.text.ParseException e) {
			// assume the server returns some kind of generic document, treat this
			// equivalent to an input/output exception.

			throw new RemoteKeySourceException("Couldn't parse remote JWK set: " + e.getMessage(), e);
		}
	}

	@Override
	public void close() throws IOException {
		// do nothing
	}

	public JWKSetHealth getHealth(boolean refresh) {
		throw new JWKSetHealthNotSupportedException("Provider " + getClass().getName() + " does not support health requests");
	}

	@Override
	public boolean supportsHealth() {
		return false;
	}

	// for testing
	ResourceRetriever getResourceRetriever() {
		return resourceRetriever;
	}
}
