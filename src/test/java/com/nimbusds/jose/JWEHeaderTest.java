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

import junit.framework.TestCase;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimNames;


/**
 * Tests JWE header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version 2022-03-07
 */
public class JWEHeaderTest extends TestCase {


	public void testMinimalConstructor() {

		JWEHeader h = new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM);

		assertEquals(JWEAlgorithm.A128KW, h.getAlgorithm());
		assertEquals(EncryptionMethod.A128GCM, h.getEncryptionMethod());
		assertNull(h.getJWKURL());
		assertNull(h.getJWK());
		assertNull(h.getX509CertURL());
		assertNull(h.getX509CertThumbprint());
		assertNull(h.getX509CertSHA256Thumbprint());
		assertNull(h.getX509CertChain());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertNull(h.getCriticalParams());
		assertNull(h.getEphemeralPublicKey());
		assertNull(h.getCompressionAlgorithm());
		assertNull(h.getAgreementPartyUInfo());
		assertNull(h.getAgreementPartyVInfo());
		assertNull(h.getPBES2Salt());
		assertEquals(0, h.getPBES2Count());
		assertNull(h.getIV());
		assertNull(h.getAuthTag());
		assertNull(h.getSenderKeyID());
		assertTrue(h.getCustomParams().isEmpty());
	}


	// https://datatracker.ietf.org/doc/html/rfc7516#section-3.3
	public void testParseExample_RFC7516_1()
		throws Exception {

		// Example header from JWE spec
		// {"alg":"RSA-OAEP","enc":"A256GCM"}
		Base64URL in = new Base64URL("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ");

		JWEHeader h = JWEHeader.parse(in);

		assertEquals(in, h.toBase64URL());

		assertNotNull(h);

		assertEquals(JWEAlgorithm.RSA_OAEP, h.getAlgorithm());
		assertEquals(EncryptionMethod.A256GCM, h.getEncryptionMethod());

		assertNull(h.getType());
		assertNull(h.getContentType());

		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ENCRYPTION_ALGORITHM));
		assertEquals(2, h.getIncludedParams().size());
	}


	// https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.2.1
	public void testParseExample_RFC7516_2()
		throws Exception {

		// Example header from JWE spec
		// {"alg":"RSA1_5","enc":"A128CBC-HS256"}
		Base64URL in = new Base64URL("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0");

		JWEHeader h = JWEHeader.parse(in);

		assertEquals(in, h.toBase64URL());

		assertNotNull(h);

		assertEquals(JWEAlgorithm.RSA1_5, h.getAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, h.getEncryptionMethod());

		assertNull(h.getType());
		assertNull(h.getContentType());

		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ENCRYPTION_ALGORITHM));
		assertEquals(2, h.getIncludedParams().size());
	}


	public void testSerializeAndParse()
		throws Exception {

		final Base64URL mod = new Base64URL("abc123");
		final Base64URL exp = new Base64URL("def456");
		final KeyUse use = KeyUse.ENCRYPTION;
		final String kid = "id-1234";
		final String skid = "sender-id-5678";

		RSAKey jwk = new RSAKey.Builder(mod, exp).keyUse(use).algorithm(JWEAlgorithm.RSA1_5).keyID(kid).build();

		List<Base64> certChain = new LinkedList<>();
		certChain.add(new Base64("asd"));
		certChain.add(new Base64("fgh"));
		certChain.add(new Base64("jkl"));

		JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A256GCM)
			.type(new JOSEObjectType("JWT"))
			.compressionAlgorithm(CompressionAlgorithm.DEF)
			.jwkURL(new URI("https://example.com/jku.json"))
			.jwk(jwk)
			.x509CertURL(new URI("https://example/cert.b64"))
			.x509CertThumbprint(new Base64URL("789iop"))
			.x509CertSHA256Thumbprint(new Base64URL("789asd"))
			.x509CertChain(certChain)
			.keyID(kid)
			.agreementPartyUInfo(new Base64URL("abc"))
			.agreementPartyVInfo(new Base64URL("xyz"))
			.pbes2Salt(new Base64URL("omg"))
			.pbes2Count(1000)
			.iv(new Base64URL("101010"))
			.authTag(new Base64URL("202020"))
			.senderKeyID(skid)
			.customParam("xCustom", "+++")
			.build();


		Base64URL base64URL = h.toBase64URL();

		// Parse back
		h = JWEHeader.parse(base64URL);

		assertEquals(JWEAlgorithm.RSA1_5, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(EncryptionMethod.A256GCM, h.getEncryptionMethod());
		assertEquals(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
		assertEquals(new URI("https://example.com/jku.json"), h.getJWKURL());
		assertEquals(kid, h.getKeyID());

		jwk = (RSAKey)h.getJWK();
		assertNotNull(jwk);
		assertEquals(new Base64URL("abc123"), jwk.getModulus());
		assertEquals(new Base64URL("def456"), jwk.getPublicExponent());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertEquals(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
		assertEquals(kid, jwk.getKeyID());

		assertEquals(new URI("https://example/cert.b64"), h.getX509CertURL());
		assertEquals(new Base64URL("789iop"), h.getX509CertThumbprint());
		assertEquals(new Base64URL("789asd"), h.getX509CertSHA256Thumbprint());

		certChain = h.getX509CertChain();
		assertEquals(3, certChain.size());
		assertEquals(new Base64("asd"), certChain.get(0));
		assertEquals(new Base64("fgh"), certChain.get(1));
		assertEquals(new Base64("jkl"), certChain.get(2));

		assertEquals(new Base64URL("abc"), h.getAgreementPartyUInfo());
		assertEquals(new Base64URL("xyz"), h.getAgreementPartyVInfo());

		assertEquals(new Base64URL("omg"), h.getPBES2Salt());
		assertEquals(1000, h.getPBES2Count());

		assertEquals(new Base64URL("101010"), h.getIV());
		assertEquals(new Base64URL("202020"), h.getAuthTag());
		
		assertEquals(skid, h.getSenderKeyID());

		assertEquals("+++", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());

		assertEquals(base64URL, h.getParsedBase64URL());

		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.TYPE));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ENCRYPTION_ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.COMPRESSION_ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.JWK_SET_URL));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.JWK));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.KEY_ID));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_URL));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_CHAIN));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.AGREEMENT_PARTY_U_INFO));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.AGREEMENT_PARTY_V_INFO));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.PBES2_SALT_INPUT));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.PBES2_COUNT));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.INITIALIZATION_VECTOR));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.AUTHENTICATION_TAG));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.SENDER_KEY_ID));
		assertTrue(h.getIncludedParams().contains("xCustom"));
		assertEquals(19, h.getIncludedParams().size());

		// Test copy constructor
		h = new JWEHeader(h);

		assertEquals(JWEAlgorithm.RSA1_5, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals(EncryptionMethod.A256GCM, h.getEncryptionMethod());
		assertEquals(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
		assertEquals(new URI("https://example.com/jku.json"), h.getJWKURL());
		assertEquals(kid, h.getKeyID());

		jwk = (RSAKey)h.getJWK();
		assertNotNull(jwk);
		assertEquals(new Base64URL("abc123"), jwk.getModulus());
		assertEquals(new Base64URL("def456"), jwk.getPublicExponent());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertEquals(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
		assertEquals(kid, jwk.getKeyID());

		assertEquals(new URI("https://example/cert.b64"), h.getX509CertURL());
		assertEquals(new Base64URL("789iop"), h.getX509CertThumbprint());
		assertEquals(new Base64URL("789asd"), h.getX509CertSHA256Thumbprint());

		certChain = h.getX509CertChain();
		assertEquals(3, certChain.size());
		assertEquals(new Base64("asd"), certChain.get(0));
		assertEquals(new Base64("fgh"), certChain.get(1));
		assertEquals(new Base64("jkl"), certChain.get(2));

		assertEquals(new Base64URL("abc"), h.getAgreementPartyUInfo());
		assertEquals(new Base64URL("xyz"), h.getAgreementPartyVInfo());

		assertEquals(new Base64URL("omg"), h.getPBES2Salt());
		assertEquals(1000, h.getPBES2Count());

		assertEquals(new Base64URL("101010"), h.getIV());
		assertEquals(new Base64URL("202020"), h.getAuthTag());
		
		assertEquals(skid, h.getSenderKeyID());

		assertEquals("+++", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());

		assertEquals(base64URL, h.getParsedBase64URL());
	}


	public void testCrit()
		throws Exception {

		Set<String> crit = new HashSet<>();
		crit.add(JWTClaimNames.ISSUED_AT);
		crit.add(JWTClaimNames.EXPIRATION_TIME);
		crit.add(JWTClaimNames.NOT_BEFORE);

		JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).
			criticalParams(crit).
			build();

		assertEquals(3, h.getCriticalParams().size());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = JWEHeader.parse(b64url);
		
		crit = h.getCriticalParams();

		assertTrue(crit.contains(JWTClaimNames.ISSUED_AT));
		assertTrue(crit.contains(JWTClaimNames.EXPIRATION_TIME));
		assertTrue(crit.contains(JWTClaimNames.NOT_BEFORE));

		assertEquals(3, crit.size());
	}


	public void testRejectNone() {

		try {
			new JWEHeader(new JWEAlgorithm("none"), EncryptionMethod.A128CBC_HS256);

			fail("Failed to raise exception");

		} catch (IllegalArgumentException e) {

			// ok
		}
	}


	public void testBuilder()
		throws Exception {
		
		JWK jwk = new RSAKeyGenerator(2048).generate().toPublicJWK();

		JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM).
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
			compressionAlgorithm(CompressionAlgorithm.DEF).
			agreementPartyUInfo(new Base64URL("qwe")).
			agreementPartyVInfo(new Base64URL("rty")).
			pbes2Salt(new Base64URL("uiop")).
			pbes2Count(1000).
			iv(new Base64URL("101010")).
			authTag(new Base64URL("202020")).
			customParam(JWTClaimNames.EXPIRATION_TIME, 123).
			customParam(JWTClaimNames.NOT_BEFORE, 456).
			build();

		assertEquals(JWEAlgorithm.A128KW, h.getAlgorithm());
		assertEquals(EncryptionMethod.A128GCM, h.getEncryptionMethod());
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
		assertEquals(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
		assertEquals("qwe", h.getAgreementPartyUInfo().toString());
		assertEquals("rty", h.getAgreementPartyVInfo().toString());
		assertEquals("uiop", h.getPBES2Salt().toString());
		assertEquals(1000, h.getPBES2Count());
		assertEquals("101010", h.getIV().toString());
		assertEquals("202020", h.getAuthTag().toString());
		assertEquals(123, ((Integer)h.getCustomParam(JWTClaimNames.EXPIRATION_TIME)).intValue());
		assertEquals(456, ((Integer)h.getCustomParam(JWTClaimNames.NOT_BEFORE)).intValue());
		assertEquals(2, h.getCustomParams().size());
		assertNull(h.getParsedBase64URL());

		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.ENCRYPTION_ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.TYPE));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.CONTENT_TYPE));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.CRITICAL));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.JWK_SET_URL));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.JWK));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_URL));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_SHA_256_THUMBPRINT));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.X_509_CERT_CHAIN));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.KEY_ID));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.COMPRESSION_ALGORITHM));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.AGREEMENT_PARTY_U_INFO));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.AGREEMENT_PARTY_V_INFO));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.PBES2_SALT_INPUT));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.PBES2_COUNT));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.INITIALIZATION_VECTOR));
		assertTrue(h.getIncludedParams().contains(HeaderParameterNames.AUTHENTICATION_TAG));
		assertTrue(h.getIncludedParams().contains(JWTClaimNames.EXPIRATION_TIME));
		assertTrue(h.getIncludedParams().contains(JWTClaimNames.NOT_BEFORE));
		assertEquals(21, h.getIncludedParams().size());
	}


	public void testBuilderWithCustomParams() {

		Map<String,Object> customParams = new HashMap<>();
		customParams.put("x", "1");
		customParams.put("y", "2");

		JWEHeader h = new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM).
			customParams(customParams).
			build();

		assertEquals("1", (String)h.getCustomParam("x"));
		assertEquals("2", (String)h.getCustomParam("y"));
		assertEquals(2, h.getCustomParams().size());
	}
	
	
	// iss #333
	public void testParseHeaderWithNullTyp()
		throws ParseException {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(HeaderParameterNames.ALGORITHM, JWEAlgorithm.DIR.getName());
		jsonObject.put(HeaderParameterNames.ENCRYPTION_ALGORITHM, EncryptionMethod.A128GCM.getName());
		jsonObject.put(HeaderParameterNames.TYPE, null);
		assertEquals(3, jsonObject.size());

		JWEHeader header = JWEHeader.parse(JSONObjectUtils.toJSONString(jsonObject));
		assertNull(header.getType());
	}
	
	
	// iss #334
	public void testParseHeaderWithNullCrit()
		throws ParseException {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(HeaderParameterNames.ALGORITHM, JWEAlgorithm.DIR.getName());
		jsonObject.put(HeaderParameterNames.ENCRYPTION_ALGORITHM, EncryptionMethod.A128GCM.getName());
		jsonObject.put(HeaderParameterNames.CRITICAL, null);
		assertEquals(3, jsonObject.size());

		JWEHeader header = JWEHeader.parse(JSONObjectUtils.toJSONString(jsonObject));
		assertNull(header.getCriticalParams());
	}
	
	
	public void testParseHeaderWithNullJWK()
		throws ParseException {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(HeaderParameterNames.ALGORITHM, JWEAlgorithm.DIR.getName());
		jsonObject.put(HeaderParameterNames.ENCRYPTION_ALGORITHM, EncryptionMethod.A128GCM.getName());
		jsonObject.put(HeaderParameterNames.JWK, null);
		assertEquals(3, jsonObject.size());
		
		JWEHeader header = JWEHeader.parse(JSONObjectUtils.toJSONString(jsonObject));
		assertNull(header.getJWK());
	}
	
	
	public void testParseHeaderWithNullZIP()
		throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(HeaderParameterNames.ALGORITHM, JWEAlgorithm.DIR.getName());
		jsonObject.put(HeaderParameterNames.ENCRYPTION_ALGORITHM, EncryptionMethod.A128GCM.getName());
		jsonObject.put(HeaderParameterNames.COMPRESSION_ALGORITHM, null);
		assertEquals(3, jsonObject.size());
		
		JWEHeader header = JWEHeader.parse(JSONObjectUtils.toJSONString(jsonObject));
		assertNull(header.getCompressionAlgorithm());
	}
	
	
	public void testBuildWithNonPublicJWK() throws JOSEException {
		
		JWK jwk = new RSAKeyGenerator(2048).generate();
		
		try {
			new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
				.jwk(jwk);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JWK must be public", e.getMessage());
		}
	}
	
	
	public void testParseHeaderWithNonPublicJWK() throws JOSEException {
		
		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
		
		Map<String, Object> jsonObject = header.toJSONObject();
		
		JWK jwk = new RSAKeyGenerator(2048).generate();
		jsonObject.put("jwk", jwk.toJSONObject());
		
		try {
			JWEHeader.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Non-public key in jwk header parameter", e.getMessage());
		}
	}
}
