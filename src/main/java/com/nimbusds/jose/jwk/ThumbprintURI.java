/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.jwk;


import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Objects;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64URL;


/**
 * JSON Web Key (JWK) thumbprint URI.
 *
 * <p>Example SHA-256 thumbprint URI:
 *
 * <pre>
 * urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
 * </pre>
 *
 * <p>See draft-ietf-oauth-jwk-thumbprint-uri-01
 *
 * @author Vladimir Dzhuvinov
 * @version 2022-02-21
 */
@Immutable
public class ThumbprintURI {
	
	
	/**
	 * The URI prefix of JWK thumbprints.
	 */
	public static final String PREFIX = "urn:ietf:params:oauth:jwk-thumbprint:";
	
	
	/**
	 * The hash algorithm.
	 */
	private final String hashAlg;
	
	
	/**
	 * The thumbprint value.
	 */
	private final Base64URL thumbprint;
	
	
	/**
	 * Creates a new JWK thumbprint URI.
	 *
	 * @param hashAlg    The hash algorithm. Must not be {@code null}.
	 * @param thumbprint The thumbprint value. Must not be {@code null}.
	 */
	public ThumbprintURI(final String hashAlg, final Base64URL thumbprint) {
		if (hashAlg == null || hashAlg.isEmpty()) {
			throw new IllegalArgumentException("The hash algorithm must not be null or empty");
		}
		this.hashAlg = hashAlg;
		
		if (thumbprint == null || thumbprint.toString().isEmpty()) {
			throw new IllegalArgumentException("The thumbprint must not be null or empty");
		}
		this.thumbprint = thumbprint;
	}
	
	
	/**
	 * Returns the hash algorithm string.
	 *
	 * @return The hash algorithm string.
	 */
	public String getAlgorithmString() {
		
		return hashAlg;
	}
	
	
	/**
	 * Returns the underlying thumbprint value.
	 *
	 * @return The thumbprint value.
	 */
	public Base64URL getThumbprint() {
		
		return thumbprint;
	}
	
	
	/**
	 * Returns the {@link URI} representation.
	 *
	 * @return The {@link URI} representation.
	 */
	public URI toURI() {
		
		return URI.create(toString());
	}
	
	
	@Override
	public String toString() {
		
		return PREFIX + hashAlg + ":" + thumbprint;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof ThumbprintURI)) return false;
		ThumbprintURI that = (ThumbprintURI) o;
		return hashAlg.equals(that.hashAlg) && getThumbprint().equals(that.getThumbprint());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(hashAlg, getThumbprint());
	}
	
	
	/**
	 * Computes the SHA-256 JWK thumbprint URI for the specified JWK.
	 *
	 * @param jwk The JWK. Must not be {@code null}.
	 *
	 * @return The SHA-256 JWK thumbprint URI.
	 *
	 * @throws JOSEException If the SHA-256 hash algorithm is not
	 *                       supported.
	 */
	public static ThumbprintURI compute(final JWK jwk)
		throws JOSEException {
		
		return new ThumbprintURI("sha-256", jwk.computeThumbprint());
	}
	
	
	/**
	 * Parses a JWK thumbprint URI from the specified URI.
	 *
	 * @param uri The URI. Must not be {@code null}.
	 *
	 * @return The JWK thumbprint URI.
	 *
	 * @throws ParseException If the URI is illegal.
	 */
	public static ThumbprintURI parse(final URI uri)
		throws ParseException {
		
		String uriString = uri.toString();
		if (! uriString.startsWith(PREFIX)) {
			throw new ParseException("Illegal JWK thumbprint prefix", 0);
		}
		
		String valuesString = uriString.substring(PREFIX.length());
		if (valuesString.isEmpty()) {
			throw new ParseException("Illegal JWK thumbprint: Missing value", 0);
		}
		
		String[] values = valuesString.split(":");
		if (values.length != 2) {
			throw new ParseException("Illegal JWK thumbprint: Unexpected number of components", 0);
		}
		if (values[0].isEmpty()) {
			throw new ParseException("Illegal JWK thumbprint: The hash algorithm must not be empty", 0);
		}
		// Empty thumbprint prevented by split method
		
		return new ThumbprintURI(values[0], new Base64URL(values[1]));
	}
	
	
	/**
	 * Parses a JWK thumbprint URI from the specified URI string.
	 *
	 * @param s The URI string. Must not be {@code null}.
	 *
	 * @return The JWK thumbprint URI.
	 *
	 * @throws ParseException If the URI string is illegal.
	 */
	public static ThumbprintURI parse(final String s)
		throws ParseException {
		
		try {
			return parse(new URI(s));
		} catch (URISyntaxException e) {
			throw new ParseException(e.getMessage(), 0);
		}
	}
}
