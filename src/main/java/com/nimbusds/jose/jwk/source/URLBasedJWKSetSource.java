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
import java.util.Objects;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthStatus;


/**
 * JWK set source that loads the keys from a {@link URL}, without health status
 * reporting.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-09
 */
@ThreadSafe
public class URLBasedJWKSetSource<C extends SecurityContext> implements JWKSetSource<C> {
	
	private final URL url;
	private final ResourceRetriever resourceRetriever;

	
	/**
	 * Creates a new URL based JWK set source.
	 *
	 * @param url               The JWK set URL. Must not be {@code null}.
	 * @param resourceRetriever The resource retriever to use. Must not
	 *                          be {@code null}.
	 */
	public URLBasedJWKSetSource(final URL url, final ResourceRetriever resourceRetriever) {
		Objects.requireNonNull(url, "The URL must not be null");
		this.url = url;
		Objects.requireNonNull(resourceRetriever, "The resource retriever must not be null");
		this.resourceRetriever = resourceRetriever;
	}
	
	
	@Override
	public JWKSet getJWKSet(final boolean forceReload, final long currentTime, final C context) throws KeySourceException {
		
		Resource resource;
		try {
			resource = resourceRetriever.retrieveResource(url);
		} catch (IOException e) {
			throw new JWKSetRetrievalException("Couldn't retrieve JWK set from URL: " + e.getMessage(), e);
		}
		
		try {
			// Note on error handling: We want to avoid any generic HTML document
			// (i.e. default HTTP error pages) and other invalid responses being accepted
			// as an empty list of JWKs. This is handled by the underlying parser;
			// it checks that the transferred document is in fact a JSON document,
			// and that the "keys" field is present.
			return JWKSet.parse(resource.getContent());
			
		} catch (Exception e) {
			// Guard against unexpected exceptions
			throw new JWKSetParseException("Unable to parse JWK set", e);
		}
	}
	
	
	@Override
	public void close() throws IOException {
		// do nothing
	}
	
	
	public HealthReport reportHealthStatus(final boolean refresh, final C context) {
		return new HealthReport(HealthStatus.NOT_SUPPORTED);
	}
}
