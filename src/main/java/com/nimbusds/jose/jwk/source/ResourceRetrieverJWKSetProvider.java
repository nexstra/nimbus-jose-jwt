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
import java.net.URL;

import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;

/**
 * Jwk provider that loads them from a {@link URL}
 */

public class ResourceRetrieverJWKSetProvider extends AbstractResourceJWKSetProvider {

	private final ResourceRetriever resourceRetriever;

	/**
	 * Creates a provider that loads from the given URL
	 *
	 * @param url			   The url of the JWKs
	 * @param resourceRetriever ResourceRetriever
	 */
	public ResourceRetrieverJWKSetProvider(URL url, ResourceRetriever resourceRetriever) {
		super(url);
		checkArgument(resourceRetriever != null, "A non-null ResourceRetriever is required");

		this.resourceRetriever = resourceRetriever;
	}

	@Override
	protected Resource getResource() throws JWKSetTransferException {
		try {
			return resourceRetriever.retrieveResource(url);
		} catch (IOException e) {
			throw new JWKSetTransferException("Couldn't retrieve remote JWK set: " + e.getMessage(), e);
		}
	}
	
	// for testing
	ResourceRetriever getResourceRetriever() {
		return resourceRetriever;
	}
}
