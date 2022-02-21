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


import java.text.ParseException;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;


public class ThumbprintURITest extends TestCase {


	public void testPrefix() {
		
		assertEquals("urn:ietf:params:oauth:jwk-thumbprint:", ThumbprintURI.PREFIX);
	}
	
	
	public void testSpecExample() throws ParseException {
		
		String hashAlg = "sha-256";
		Base64URL value = new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
		
		ThumbprintURI thumbprintURI = new ThumbprintURI(hashAlg, value);
		assertEquals(hashAlg, thumbprintURI.getAlgorithmString());
		assertEquals(value, thumbprintURI.getThumbprint());
		
		assertEquals("urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", thumbprintURI.toString());
		assertEquals("urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", thumbprintURI.toURI().toString());
		
		thumbprintURI = ThumbprintURI.parse(thumbprintURI.toString());
		assertEquals(value, thumbprintURI.getThumbprint());
		
		thumbprintURI = ThumbprintURI.parse(thumbprintURI.toURI());
		assertEquals(value, thumbprintURI.getThumbprint());
		
		assertEquals("Equality", thumbprintURI, ThumbprintURI.parse(thumbprintURI.toURI()));
		assertEquals("Hash code", thumbprintURI.hashCode(), ThumbprintURI.parse(thumbprintURI.toURI()).hashCode());
	}
	
	
	public void testCompute_sha256() throws JOSEException {
		
		RSAKey rsaKey = new RSAKeyGenerator(2048)
			.generate();
		
		ThumbprintURI thumbprintURI = rsaKey.computeThumbprintURI();
		
		assertEquals("sha-256", thumbprintURI.getAlgorithmString());
		
		assertEquals(ThumbprintURI.PREFIX + "sha-256:" + ThumbprintUtils.compute(rsaKey), thumbprintURI.toString());
		
		assertEquals(thumbprintURI, ThumbprintURI.compute(rsaKey));
	}
	
	
	public void testConstructor_nullAlg() {
		
		try {
			new ThumbprintURI(null, new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The hash algorithm must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testConstructor_emptyAlg() {
		
		try {
			new ThumbprintURI("", new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The hash algorithm must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testConstructor_nullThumbprint() {
		
		try {
			new ThumbprintURI("sha-256", null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The thumbprint must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testConstructor_emptyThumbprint() {
		
		try {
			new ThumbprintURI("sha-256", new Base64URL(""));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The thumbprint must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testParse_illegalPrefix() {
		
		try {
			ThumbprintURI.parse("urn:a:b:c");
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal JWK thumbprint prefix", e.getMessage());
		}
	}
	
	
	public void testParse_emptyValuesString() {
		
		try {
			ThumbprintURI.parse(ThumbprintURI.PREFIX + "");
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal JWK thumbprint: Missing value", e.getMessage());
		}
	}
	
	
	public void testParse_emptyAlg() {
		
		try {
			ThumbprintURI.parse(ThumbprintURI.PREFIX + ":NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal JWK thumbprint: The hash algorithm must not be empty", e.getMessage());
		}
	}
	
	
	public void testParse_missingThumbprint() {
		
		try {
			ThumbprintURI.parse(ThumbprintURI.PREFIX + "sha-256");
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal JWK thumbprint: Unexpected number of components", e.getMessage());
		}
	}
	
	
	public void testParse_emptyThumbprint() {
		
		try {
			ThumbprintURI.parse(ThumbprintURI.PREFIX + "sha-256:");
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal JWK thumbprint: Unexpected number of components", e.getMessage());
		}
	}
}
