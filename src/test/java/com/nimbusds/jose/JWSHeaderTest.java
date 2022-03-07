/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
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

package com.nimbusds.jose;


import java.net.URI;
import java.text.ParseException;
import java.util.*;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimNames;
import junit.framework.TestCase;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Tests JWS header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 2022-03-07
 */
public class JWSHeaderTest extends TestCase {
	
	
	public void testRegisteredParamNames() {
		
		Set<String> paramNames = JWSHeader.getRegisteredParameterNames();
		assertTrue(paramNames.contains(HeaderParameterNames.ALGORITHM));
		assertTrue(paramNames.contains(HeaderParameterNames.JWK_SET_URL));
		assertTrue(paramNames.contains(HeaderParameterNames.JWK));
		assertTrue(paramNames.contains(HeaderParameterNames.X_509_CERT_URL));
		assertTrue(paramNames.contains(HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT));
		assertTrue(paramNames.contains(HeaderParameterNames.X_509_CERT_SHA_256_THUMBPRINT));
		assertTrue(paramNames.contains(HeaderParameterNames.X_509_CERT_CHAIN));
		assertTrue(paramNames.contains(HeaderParameterNames.KEY_ID));
		assertTrue(paramNames.contains(HeaderParameterNames.TYPE));
		assertTrue(paramNames.contains(HeaderParameterNames.CONTENT_TYPE));
		assertTrue(paramNames.contains(HeaderParameterNames.CRITICAL));
		assertTrue(paramNames.contains(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD));
		assertEquals(12, paramNames.size());
	}


	public void testMinimalConstructor() {

		JWSHeader h = new JWSHeader(JWSAlgorithm.HS256);

		assertEquals(JWSAlgorithm.HS256, h.getAlgorithm());
		assertNull(h.getJWKURL());
		assertNull(h.getJWK());
		assertNull(h.getX509CertURL());
		assertNull(h.getX509CertThumbprint());
		assertNull(h.getX509CertSHA256Thumbprint());
		assertNull(h.getX509CertChain());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertNull(h.getCriticalParams());
		assertTrue(h.isBase64URLEncodePayload());
		assertTrue(h.getCustomParams().isEmpty());
		
		Map<String, Object> o = h.toJSONObject();
		assertEquals(h.getAlgorithm().getName(), o.get(HeaderParameterNames.ALGORITHM));
		assertEquals(1, o.size());
	}


	public void testSerializeAndParse()
		throws Exception {

		Set<String> crit = new HashSet<>();
		crit.add(JWTClaimNames.ISSUED_AT);
		crit.add(JWTClaimNames.EXPIRATION_TIME);
		crit.add(JWTClaimNames.NOT_BEFORE);

		final Base64URL mod = new Base64URL("abc123");
		final Base64URL exp = new Base64URL("def456");
		final KeyUse use = KeyUse.ENCRYPTION;
		final String kid = "1234";

		RSAKey jwk = new RSAKey.Builder(mod, exp).keyUse(use).algorithm(JWEAlgorithm.RSA1_5).keyID(kid).build();

		List<Base64> certChain = new LinkedList<>();
		certChain.add(new Base64("asd"));
		certChain.add(new Base64("fgh"));
		certChain.add(new Base64("jkl"));

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.RS256).
			type(new JOSEObjectType("JWT")).
			contentType("application/json").
			criticalParams(crit).
			jwkURL(new URI("https://example.com/jku.json")).
			jwk(jwk).
			x509CertURL(new URI("https://example/cert.b64")).
			x509CertThumbprint(new Base64URL("789iop")).
			x509CertSHA256Thumbprint(new Base64URL("789asd")).
			x509CertChain(certChain).
			keyID("1234").
			customParam("xCustom", "+++").
			build();


		Base64URL base64URL = h.toBase64URL();

		// Parse back
		h = JWSHeader.parse(base64URL);

		assertEquals(JWSAlgorithm.RS256, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertTrue(h.getCriticalParams().contains(JWTClaimNames.ISSUED_AT));
		assertTrue(h.getCriticalParams().contains(JWTClaimNames.EXPIRATION_TIME));
		assertTrue(h.getCriticalParams().contains(JWTClaimNames.NOT_BEFORE));
		assertEquals(3, h.getCriticalParams().size());
		assertEquals("application/json", h.getContentType());
		assertEquals(new URI("https://example.com/jku.json"), h.getJWKURL());
		assertEquals("1234", h.getKeyID());
		assertTrue(h.isBase64URLEncodePayload());

		jwk = (RSAKey)h.getJWK();
		assertNotNull(jwk);
		assertEquals(new Base64URL("abc123"), jwk.getModulus());
		assertEquals(new Base64URL("def456"), jwk.getPublicExponent());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertEquals(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
		assertEquals("1234", jwk.getKeyID());

		assertEquals(new URI("https://example/cert.b64"), h.getX509CertURL());
		assertEquals(new Base64URL("789iop"), h.getX509CertThumbprint());
		assertEquals(new Base64URL("789asd"), h.getX509CertSHA256Thumbprint());

		certChain = h.getX509CertChain();
		assertEquals(3, certChain.size());
		assertEquals(new Base64("asd"), certChain.get(0));
		assertEquals(new Base64("fgh"), certChain.get(1));
		assertEquals(new Base64("jkl"), certChain.get(2));

		assertEquals("+++", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());

		assertEquals(base64URL, h.getParsedBase64URL());

		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.TYPE));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.CONTENT_TYPE));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.CRITICAL));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.JWK_SET_URL));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.JWK));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.KEY_ID));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_URL));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_CHAIN));
		assertTrue(h.getIncludedParams().contains("xCustom"));
		assertEquals(12, h.getIncludedParams().size());

		// Test copy constructor
		h = new JWSHeader(h);

		assertEquals(JWSAlgorithm.RS256, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertTrue(h.getCriticalParams().contains(JWTClaimNames.ISSUED_AT));
		assertTrue(h.getCriticalParams().contains(JWTClaimNames.EXPIRATION_TIME));
		assertTrue(h.getCriticalParams().contains(JWTClaimNames.NOT_BEFORE));
		assertEquals(3, h.getCriticalParams().size());
		assertEquals("application/json", h.getContentType());
		assertEquals(new URI("https://example.com/jku.json"), h.getJWKURL());
		assertEquals("1234", h.getKeyID());
		assertTrue(h.isBase64URLEncodePayload());

		jwk = (RSAKey)h.getJWK();
		assertNotNull(jwk);
		assertEquals(new Base64URL("abc123"), jwk.getModulus());
		assertEquals(new Base64URL("def456"), jwk.getPublicExponent());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertEquals(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
		assertEquals("1234", jwk.getKeyID());

		assertEquals(new URI("https://example/cert.b64"), h.getX509CertURL());
		assertEquals(new Base64URL("789iop"), h.getX509CertThumbprint());
		assertEquals(new Base64URL("789asd"), h.getX509CertSHA256Thumbprint());

		certChain = h.getX509CertChain();
		assertEquals(3, certChain.size());
		assertEquals(new Base64("asd"), certChain.get(0));
		assertEquals(new Base64("fgh"), certChain.get(1));
		assertEquals(new Base64("jkl"), certChain.get(2));

		assertEquals("+++", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());

		assertEquals(base64URL, h.getParsedBase64URL());
	}


	public void testParseJSON()
		throws Exception {

		// Example header from JWS spec

		String s = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";

		JWSHeader h = JWSHeader.parse(s);

		assertNotNull(h);

		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(JWSAlgorithm.HS256, h.getAlgorithm());
		assertNull(h.getContentType());

		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.TYPE));
		assertEquals(2, h.getIncludedParams().size());
	}


	public void testParseBase64URL()
		throws Exception {

		// Example header from JWS spec

		Base64URL in = new Base64URL("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

		JWSHeader h = JWSHeader.parse(in);

		assertEquals(in, h.toBase64URL());

		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(JWSAlgorithm.HS256, h.getAlgorithm());
		assertNull(h.getContentType());
	}


	public void testCrit()
		throws Exception {

		Set<String> crit = new HashSet<>();
		crit.add(JWTClaimNames.ISSUED_AT);
		crit.add(JWTClaimNames.EXPIRATION_TIME);
		crit.add(JWTClaimNames.NOT_BEFORE);

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.RS256).
			criticalParams(crit).
			build();

		assertEquals(3, h.getCriticalParams().size());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = JWSHeader.parse(b64url);
		
		crit = h.getCriticalParams();

		assertTrue(crit.contains(JWTClaimNames.ISSUED_AT));
		assertTrue(crit.contains(JWTClaimNames.EXPIRATION_TIME));
		assertTrue(crit.contains(JWTClaimNames.NOT_BEFORE));

		assertEquals(3, crit.size());
	}


	public void testRejectNone() {

		try {
			new JWSHeader(new JWSAlgorithm("none"));

			fail("Failed to raise exception");

		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testBuilder()
		throws Exception {
		
		JWK jwk = new RSAKeyGenerator(2048).generate().toPublicJWK();

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.HS256).
			type(JOSEObjectType.JOSE).
			contentType("application/json").
			criticalParams(new HashSet<>(Arrays.asList(JWTClaimNames.EXPIRATION_TIME, JWTClaimNames.NOT_BEFORE))).
			jwkURL(new URI("http://example.com/jwk.json")).
			jwk(jwk).
			x509CertURL(new URI("http://example.com/cert.pem")).
			x509CertThumbprint(new Base64URL("abc")).
			x509CertSHA256Thumbprint(new Base64URL("abc256")).
			x509CertChain(Arrays.asList(new Base64("abc"), new Base64("def"))).
			keyID("123").
			customParam(JWTClaimNames.EXPIRATION_TIME, 123).
			customParam(JWTClaimNames.NOT_BEFORE, 456).
			build();

		assertEquals(JWSAlgorithm.HS256, h.getAlgorithm());
		assertEquals(JOSEObjectType.JOSE, h.getType());
		assertEquals("application/json", h.getContentType());
		assertTrue(h.getCriticalParams().contains(JWTClaimNames.EXPIRATION_TIME));
		assertTrue(h.getCriticalParams().contains(JWTClaimNames.NOT_BEFORE));
		assertEquals(2, h.getCriticalParams().size());
		assertEquals("http://example.com/jwk.json", h.getJWKURL().toString());
		assertEquals(jwk, h.getJWK());
		assertEquals("http://example.com/cert.pem", h.getX509CertURL().toString());
		assertEquals("abc", h.getX509CertThumbprint().toString());
		assertEquals("abc256", h.getX509CertSHA256Thumbprint().toString());
		assertEquals("abc", h.getX509CertChain().get(0).toString());
		assertEquals("def", h.getX509CertChain().get(1).toString());
		assertEquals(2, h.getX509CertChain().size());
		assertEquals("123", h.getKeyID());
		assertEquals(123, ((Integer)h.getCustomParam(JWTClaimNames.EXPIRATION_TIME)).intValue());
		assertEquals(456, ((Integer)h.getCustomParam(JWTClaimNames.NOT_BEFORE)).intValue());
		assertEquals(2, h.getCustomParams().size());
		assertNull(h.getParsedBase64URL());

		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.TYPE));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.CONTENT_TYPE));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.CRITICAL));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.JWK_SET_URL));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.JWK));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_URL));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_CHAIN));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.KEY_ID));
		assertTrue(h.getIncludedParams().contains(JWTClaimNames.EXPIRATION_TIME));
		assertTrue(h.getIncludedParams().contains(JWTClaimNames.NOT_BEFORE));
		assertEquals(13, h.getIncludedParams().size());
	}


	public void testBuilderWithCustomParams() {

		Map<String,Object> customParams = new HashMap<>();
		customParams.put("x", "1");
		customParams.put("y", "2");

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.HS256).
			customParams(customParams).
			build();

		assertEquals("1", (String)h.getCustomParam("x"));
		assertEquals("2", (String)h.getCustomParam("y"));
		assertEquals(2, h.getCustomParams().size());
	}


	public void testImmutableCustomParams() {

		Map<String,Object> customParams = new HashMap<>();
		customParams.put("x", "1");
		customParams.put("y", "2");

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.HS256).
			customParams(customParams).
			build();

		try {
			h.getCustomParams().put("x", "3");
			fail();
		} catch (UnsupportedOperationException e) {
			// ok
		}
	}


	public void testImmutableCritHeaders() {

		JWSHeader h = new JWSHeader.Builder(JWSAlgorithm.HS256).
			criticalParams(new HashSet<>(Arrays.asList(JWTClaimNames.EXPIRATION_TIME, JWTClaimNames.NOT_BEFORE))).
			build();

		try {
			h.getCriticalParams().remove(JWTClaimNames.EXPIRATION_TIME);
			fail();
		} catch (UnsupportedOperationException e) {
			// ok
		}
	}
	
	
	// https://tools.ietf.org/html/rfc7797
	public void testB64_builder() throws ParseException {
		
		// Builder
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
			.base64URLEncodePayload(false)
			.criticalParams(Collections.singleton(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD))
			.build();
		
		assertEquals(JWSAlgorithm.RS256, header.getAlgorithm());
		assertFalse(header.isBase64URLEncodePayload());
		assertEquals(Collections.singleton(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD), header.getCriticalParams());
		
		assertTrue(header.getIncludedParams().contains(HeaderParameterNames.ALGORITHM));
		assertTrue(header.getIncludedParams().contains(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD));
		assertTrue(header.getIncludedParams().contains(HeaderParameterNames.CRITICAL));
		assertEquals(3, header.getIncludedParams().size());
		
		// Builder copy constructor
		header = new JWSHeader.Builder(header)
			.build();
		
		assertEquals(JWSAlgorithm.RS256, header.getAlgorithm());
		assertFalse(header.isBase64URLEncodePayload());
		assertEquals(Collections.singleton(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD), header.getCriticalParams());
		
		assertTrue(header.getIncludedParams().contains(HeaderParameterNames.ALGORITHM));
		assertTrue(header.getIncludedParams().contains(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD));
		assertTrue(header.getIncludedParams().contains(HeaderParameterNames.CRITICAL));
		assertEquals(3, header.getIncludedParams().size());
		
		// Serialisation
		Map<String, Object> o = header.toJSONObject();
		assertEquals(JWSAlgorithm.RS256.getName(), o.get(HeaderParameterNames.ALGORITHM));
		assertFalse(JSONObjectUtils.getBoolean(o, HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD));
		assertEquals(Collections.singletonList(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD), JSONObjectUtils.getStringList(o, HeaderParameterNames.CRITICAL));
		assertEquals(3, o.size());
		
		Base64URL base64URL = header.toBase64URL();
		
		// Parse
		header = JWSHeader.parse(base64URL);
		
		assertEquals(JWSAlgorithm.RS256, header.getAlgorithm());
		assertFalse(header.isBase64URLEncodePayload());
		assertEquals(Collections.singleton(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD), header.getCriticalParams());
		
		assertEquals(base64URL, header.getParsedBase64URL());
	}
	
	
	public void testB64_parseExampleHeader() throws ParseException {
		
		String s = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19";
		JWSHeader header = JWSHeader.parse(new Base64URL(s));
		assertEquals(JWSAlgorithm.HS256, header.getAlgorithm());
		assertFalse(header.isBase64URLEncodePayload());
		assertEquals(Collections.singleton(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD), header.getCriticalParams());
		
		assertTrue(header.getIncludedParams().contains(HeaderParameterNames.ALGORITHM));
		assertTrue(header.getIncludedParams().contains(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD));
		assertTrue(header.getIncludedParams().contains(HeaderParameterNames.CRITICAL));
		assertEquals(3, header.getIncludedParams().size());
	}


	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/154/list-of-strings-as-custom-claim-will-add
	public void testParseCustomParamListOfStrings()
		throws ParseException {

		String json = "{ \"alg\":\"HS256\", \"aud\":[\"a\",\"b\"],\"test\":[\"a\",\"b\"] }";

		JWSHeader header = JWSHeader.parse(json);

		assertEquals(JWSAlgorithm.HS256, header.getAlgorithm());

		List<?> audList = (List)header.getCustomParam(JWTClaimNames.AUDIENCE);
		assertEquals("a", audList.get(0));
		assertEquals("b", audList.get(1));
		assertEquals(2, audList.size());

		List<?> testList = (List)header.getCustomParam("test");
		assertEquals("a", testList.get(0));
		assertEquals("b", testList.get(1));
		assertEquals(2, testList.size());
	}


	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/154/list-of-strings-as-custom-claim-will-add
	public void testSetCustomParamListOfStrings() {

		List<String> audList = new LinkedList<>();
		audList.add("a");
		audList.add("b");

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
			.customParam(JWTClaimNames.AUDIENCE, audList)
			.build();

		assertTrue( JSONObjectUtils.toJSONString(header.toJSONObject()).contains("\"aud\":[\"a\",\"b\"]"));
	}
	
	
	// iss #208
	public void testHeaderParameterAsJSONObject()
		throws Exception {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", "value");
		
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
			.customParam("prm", jsonObject)
			.build();
		
		jsonObject = (Map) header.getCustomParam("prm");
		assertEquals("value", jsonObject.get("key"));
		assertEquals(1, jsonObject.size());
		
		Map<String, Object> headerJSONObject = header.toJSONObject();
		assertEquals("HS256", headerJSONObject.get(HeaderParameterNames.ALGORITHM));
		jsonObject = (Map) headerJSONObject.get("prm");
		assertEquals("value", jsonObject.get("key"));
		assertEquals(1, jsonObject.size());
		assertEquals(2, headerJSONObject.size());
		
		Base64URL encodedHeader = header.toBase64URL();
		
		header = JWSHeader.parse(encodedHeader);
		
		jsonObject = (Map<String, Object> ) header.getCustomParam("prm");
		assertEquals("value", jsonObject.get("key"));
		assertEquals(1, jsonObject.size());
		
		headerJSONObject = header.toJSONObject();
		assertEquals("HS256", headerJSONObject.get(HeaderParameterNames.ALGORITHM));
		jsonObject = (Map<String, Object> ) headerJSONObject.get("prm");
		assertEquals("value", jsonObject.get("key"));
		assertEquals(1, jsonObject.size());
		assertEquals(2, headerJSONObject.size());
	}
	
	
	// iss #282
	public void testParseHeaderWithNullParamValue()
		throws Exception {
		
		String header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6bnVsbH0";
		
		Map<String, Object>  jsonObject = JSONObjectUtils.parse(new Base64URL(header).decodeToString());
		
		assertEquals("HS256", jsonObject.get(HeaderParameterNames.ALGORITHM));
		assertEquals("JWT", jsonObject.get(HeaderParameterNames.TYPE));
		assertNull(jsonObject.get(HeaderParameterNames.CONTENT_TYPE));
		assertEquals(3, jsonObject.size());
		
		JWSHeader jwsHeader = JWSHeader.parse(new Base64URL(header));
		
		assertEquals(JWSAlgorithm.HS256, jwsHeader.getAlgorithm());
		assertEquals(JOSEObjectType.JWT, jwsHeader.getType());
		assertNull(jwsHeader.getContentType());
		assertEquals(2, jwsHeader.toJSONObject().size());
	}
	
	// iss #333
	public void testParseHeaderWithNullTyp()
		throws ParseException {
		
		Map<String, Object>  jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(HeaderParameterNames.ALGORITHM, "HS256");
		jsonObject.put(HeaderParameterNames.TYPE, null);
		assertEquals(2, jsonObject.size());
		
		Header header = JWSHeader.parse(JSONObjectUtils.toJSONString(jsonObject));
		assertNull(header.getType());
	}
	
	// iss #334
	public void testParseHeaderWithNullCrit()
		throws ParseException {
		
		Map<String, Object>  jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(HeaderParameterNames.ALGORITHM, "HS256");
		jsonObject.put(HeaderParameterNames.CRITICAL, null);
		assertEquals(2, jsonObject.size());
		
		Header header = JWSHeader.parse(JSONObjectUtils.toJSONString(jsonObject));
		assertNull(header.getCriticalParams());
	}
	
	
	public void testParseHeaderWithNullJWK()
		throws ParseException {
		
		Map<String, Object>  jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(HeaderParameterNames.ALGORITHM, "HS256");
		jsonObject.put(HeaderParameterNames.JWK, null);
		assertEquals(2, jsonObject.size());
		
		JWSHeader header = JWSHeader.parse(JSONObjectUtils.toJSONString(jsonObject));
		assertNull(header.getJWK());
	}
	
	
	public void testParsePlainHeader() {
		
		Map<String, Object>  jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(HeaderParameterNames.ALGORITHM, "none");
		
		try {
			JWSHeader.parse(JSONObjectUtils.toJSONString(jsonObject));
			fail();
		} catch (ParseException e) {
			assertEquals("Not a JWS header", e.getMessage());
		}
	}
	
	
	public void testBuildWithNonPublicJWK() throws JOSEException {
		
		JWK jwk = new RSAKeyGenerator(2048).generate();
		
		try {
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.jwk(jwk);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JWK must be public", e.getMessage());
		}
	}
	
	
	public void testParseHeaderWithNonPublicJWK() throws JOSEException {
		
		JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);
		
		Map<String, Object> jsonObject = header.toJSONObject();
		
		JWK jwk = new RSAKeyGenerator(2048).generate();
		jsonObject.put("jwk", jwk.toJSONObject());
		
		try {
			JWSHeader.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Non-public key in jwk header parameter", e.getMessage());
		}
	}
}

