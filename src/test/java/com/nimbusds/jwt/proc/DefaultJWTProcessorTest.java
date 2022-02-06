/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2019, Connect2id Ltd.
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

package com.nimbusds.jwt.proc;


import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import junit.framework.TestCase;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URL;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;


/**
 * Tests the default JWT processor.
 *
 * @version 2021-06-05
 */
public class DefaultJWTProcessorTest extends TestCase {


	public void testConstructor() {

		ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();

		assertEquals(DefaultJOSEObjectTypeVerifier.JWT, processor.getJWSTypeVerifier());
		assertEquals(DefaultJOSEObjectTypeVerifier.JWT, processor.getJWETypeVerifier());
		
		assertNull(processor.getJWSKeySelector());
		assertNull(processor.getJWEKeySelector());

		assertTrue(processor.getJWSVerifierFactory() instanceof DefaultJWSVerifierFactory);
		assertTrue(processor.getJWEDecrypterFactory() instanceof DefaultJWEDecrypterFactory);

		assertTrue(processor.getJWTClaimsSetVerifier() instanceof DefaultJWTClaimsVerifier);
	}


	public void testVerifyClaimsAllow()
		throws Exception {

		JWTClaimsSet claims = new JWTClaimsSet.Builder()
			.issuer("https://openid.c2id.com")
			.subject("alice")
			.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

		jwt.sign(new MACSigner(key));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				return Collections.singletonList(key);
			}
		});

		processor.setJWTClaimsSetVerifier(new JWTClaimsSetVerifier<SimpleSecurityContext>() {
			@Override
			public void verify(JWTClaimsSet claimsSet, SimpleSecurityContext context)
				throws BadJWTException {
				
				if (claimsSet.getIssuer() == null || !claimsSet.getIssuer().equals("https://openid.c2id.com"))
					throw new BadJWTException("Unexpected/missing issuer");
			}
		});
		
		assertNotNull(processor.getJWTClaimsSetVerifier());

		assertEquals("alice", processor.process(jwt.serialize(), null).getSubject());
		assertEquals("https://openid.c2id.com", processor.process(jwt.serialize(), null).getIssuer());
	}
	
	
	public void testProcessWithClaimsAwareKeySelector()
		throws Exception {
		
		final JWTClaimsSet claims = new JWTClaimsSet.Builder()
			.issuer("https://openid.c2id.com")
			.subject("alice")
			.build();
		
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
		
		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey key = new SecretKeySpec(keyBytes, "HMAC");
		
		jwt.sign(new MACSigner(key));
		
		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();
		
		processor.setJWTClaimsSetAwareJWSKeySelector(new JWTClaimsSetAwareJWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectKeys(JWSHeader header, JWTClaimsSet parsedClaimsSet, SimpleSecurityContext context) {
				assertEquals(claims, parsedClaimsSet);
				return Collections.singletonList(key);
			}
		});
		
		processor.setJWTClaimsSetVerifier(new JWTClaimsSetVerifier<SimpleSecurityContext>() {
			@Override
			public void verify(JWTClaimsSet claimsSet, SimpleSecurityContext context)
				throws BadJWTException {
				
				if (claimsSet.getIssuer() == null || !claimsSet.getIssuer().equals("https://openid.c2id.com"))
					throw new BadJWTException("Unexpected/missing issuer");
			}
		});

		assertNotNull(processor.getJWTClaimsSetVerifier());

		assertEquals("alice", processor.process(jwt.serialize(), null).getSubject());
		assertEquals("https://openid.c2id.com", processor.process(jwt.serialize(), null).getIssuer());
	}
	
	
	
	public void testProcessWithClaimsAwareKeySelector_noKeyCandidates()
		throws Exception {
		
		final JWTClaimsSet claims = new JWTClaimsSet.Builder()
			.issuer("https://openid.c2id.com")
			.subject("alice")
			.build();
		
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
		
		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey key = new SecretKeySpec(keyBytes, "HMAC");
		
		jwt.sign(new MACSigner(key));
		
		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();
		
		processor.setJWTClaimsSetAwareJWSKeySelector(new JWTClaimsSetAwareJWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectKeys(JWSHeader header, JWTClaimsSet parsedClaimsSet, SimpleSecurityContext context) {
				assertEquals(claims, parsedClaimsSet);
				return Collections.emptyList();
			}
		});
		
		processor.setJWTClaimsSetVerifier(new JWTClaimsSetVerifier<SimpleSecurityContext>() {
			@Override
			public void verify(JWTClaimsSet claimsSet, SimpleSecurityContext context)
				throws BadJWTException {
				
				if (claimsSet.getIssuer() == null || !claimsSet.getIssuer().equals("https://openid.c2id.com"))
					throw new BadJWTException("Unexpected/missing issuer");
			}
		});

		try {
			processor.process(jwt.serialize(), null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: Another algorithm expected, or no matching key(s) found", e.getMessage());
		}
	}


	public void testVerifyClaimsDeny()
		throws Exception {

		JWTClaimsSet claims = new JWTClaimsSet.Builder()
			.issuer("https://test.c2id.com")
			.subject("alice")
			.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

		jwt.sign(new MACSigner(key));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				return Collections.singletonList(key);
			}
		});

		processor.setJWTClaimsSetVerifier(new JWTClaimsSetVerifier<SimpleSecurityContext>() {
			@Override
			public void verify(JWTClaimsSet claimsSet, SimpleSecurityContext context)
				throws BadJWTException {
				
				if (claimsSet.getIssuer() == null || !claimsSet.getIssuer().equals("https://openid.c2id.com"))
					throw new BadJWTException("Unexpected/missing issuer");
			}
		});
		
		assertNotNull(processor.getJWTClaimsSetVerifier());

		try {
			processor.process(jwt.serialize(), null);
			fail();
		} catch (BadJWTException e) {

			assertEquals("Unexpected/missing issuer", e.getMessage());
		}
	}


	public void testProcessInvalidHmac()
		throws Exception {

		JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey invalidKey = new SecretKeySpec(keyBytes, "HMAC");

		jwt.sign(new MACSigner(invalidKey));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				byte[] keyBytes = new byte[32];
				new SecureRandom().nextBytes(keyBytes);
				final SecretKey validKey = new SecretKeySpec(keyBytes, "HMAC");
				return Arrays.asList(new SecretKeySpec(new byte[32], "HMAC"), validKey);
			}
		});

		try {
			processor.process(jwt, null);
			fail();
		} catch (BadJWSException e) {
			assertEquals("Signed JWT rejected: Invalid signature", e.getMessage());
		}
	}


	public void testProcessHmacJWTWithTwoKeyCandidates()
		throws Exception {

		JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

		jwt.sign(new MACSigner(key));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				// first key candidate invalid, the second is correct
				return Arrays.asList(new SecretKeySpec(new byte[32], "HMAC"), key);
			}
		});

		assertEquals("alice", processor.process(jwt, null).getSubject());
		assertEquals("alice", processor.process(jwt.serialize(), null).getSubject());
	}


	public void testProcessEncryptedJWTWithTwoKeyCandidates()
		throws Exception {

		JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();
		EncryptedJWT jwt = new EncryptedJWT(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM), claims);

		byte[] keyBytes = new byte[16];
		new SecureRandom().nextBytes(keyBytes);

		final SecretKey key = new SecretKeySpec(keyBytes, "AES");

		Security.addProvider(BouncyCastleProviderSingleton.getInstance());

		jwt.encrypt(new DirectEncrypter(key));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWEKeySelector(new JWEKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWEKeys(JWEHeader header, SimpleSecurityContext context) {
				// First key invalid, second valid
				return Arrays.asList(new SecretKeySpec(new byte[16], "AES"), key);
			}
		});

		assertEquals("alice", processor.process(jwt, null).getSubject());
		assertEquals("alice", processor.process(jwt.serialize(), null).getSubject());

		Security.removeProvider(BouncyCastleProviderSingleton.getInstance().getName());
	}


	public void testProcessNestedJWT()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7519#appendix-A.2

		String jwt = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU"+
			"In0."+
			"g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M"+
			"qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE"+
			"b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh"+
			"DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D"+
			"YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq"+
			"JGTO_z3Wfo5zsqwkxruxwA."+
			"UmVkbW9uZCBXQSA5ODA1Mg."+
			"VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB"+
			"BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT"+
			"-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10"+
			"l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY"+
			"Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr"+
			"ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2"+
			"8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE"+
			"l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U"+
			"zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd"+
			"_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ."+
			"AVO9iT5AV4CzvDJCdhSFlQ";

		ConfigurableJWTProcessor<SimpleSecurityContext> joseProcessor = new DefaultJWTProcessor<>();
		joseProcessor.setJWTClaimsSetVerifier(null); // Remove claims verifier, JWT past expiration timestamp

		joseProcessor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {

				if (header.getAlgorithm().equals(JWSAlgorithm.RS256)) {

					String jwk = "{\"kty\":\"RSA\"," +
						"\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" +
						"HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
						"D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" +
						"SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
						"MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
						"NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\"," +
						"\"e\":\"AQAB\"," +
						"\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I" +
						"jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0" +
						"BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn" +
						"439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT" +
						"CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh" +
						"BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"," +
						"\"p\":\"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi" +
						"YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG" +
						"BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\"," +
						"\"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa" +
						"ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA" +
						"-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc\"," +
						"\"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q" +
						"CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb" +
						"34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\"," +
						"\"dq\":\"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa" +
						"7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky" +
						"NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\"," +
						"\"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o" +
						"y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU" +
						"W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U\"" +
						"}";

					try {
						Key rsaPublicKey = RSAKey.parse(jwk).toRSAPublicKey();
						return Collections.singletonList(rsaPublicKey);

					} catch (Exception e) {
						fail(e.getMessage());
					}
				}
				return null;
			}
		});

		joseProcessor.setJWEKeySelector(new JWEKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWEKeys(JWEHeader header, SimpleSecurityContext context) {

				// {"alg":"RSA1_5","enc":"A128CBC-HS256","cty":"JWT"}
				if (header.getAlgorithm().equals(JWEAlgorithm.RSA1_5) && header.getEncryptionMethod().equals(EncryptionMethod.A128CBC_HS256)) {

					String jwk = "{\"kty\":\"RSA\"," +
						"\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl" +
						"UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre" +
						"cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_" +
						"7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI" +
						"Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU" +
						"7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\"," +
						"\"e\":\"AQAB\"," +
						"\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq" +
						"1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry" +
						"nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_" +
						"0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj" +
						"-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj" +
						"T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\"," +
						"\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68" +
						"ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP" +
						"krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\"," +
						"\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y" +
						"BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN" +
						"-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\"," +
						"\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv" +
						"ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra" +
						"Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\"," +
						"\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff" +
						"7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_" +
						"odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\"," +
						"\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC" +
						"tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ" +
						"B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\"" +
						"}";

					try {
						Key rsaPrivateKey = RSAKey.parse(jwk).toRSAPrivateKey();
						return Collections.singletonList(rsaPrivateKey);

					} catch (Exception e) {
						fail(e.getMessage());
					}
				}

				return null;
			}
		});


		assertNotNull(joseProcessor.getJWSKeySelector());
		assertNotNull(joseProcessor.getJWEKeySelector());

		JWTClaimsSet claims = joseProcessor.process(jwt, new SimpleSecurityContext());

		assertEquals("joe", claims.getIssuer());
		assertEquals(1300819380L * 1000L, claims.getExpirationTime().getTime());
		assertTrue(claims.getBooleanClaim("http://example.com/is_root"));
		assertEquals(3, claims.getClaims().size());
	}


	public void testRejectPlain()
		throws Exception {

		JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();

		PlainJWT jwt = new PlainJWT(claims);

		try {
			new DefaultJWTProcessor<>().process(jwt, null);
		} catch (BadJOSEException e) {
			assertEquals("Unsecured (plain) JWTs are rejected, extend class to handle", e.getMessage());
		}

		try {
			new DefaultJWTProcessor<>().process(jwt.serialize(), null);
		} catch (BadJOSEException e) {
			assertEquals("Unsecured (plain) JWTs are rejected, extend class to handle", e.getMessage());
		}
	}


	public void testNoJWSKeyCandidates()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7515#appendix-A.1
		String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"+
			"."+
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"+
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"+
			"."+
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				return new LinkedList<>(); // empty
			}
		});

		try {
			processor.process(jws, null);
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: Another algorithm expected, or no matching key(s) found", e.getMessage());
		}
	}


	public void testNoJWEKeyCandidates()
		throws Exception {

		String jwt = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU"+
			"In0."+
			"g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M"+
			"qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE"+
			"b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh"+
			"DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D"+
			"YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq"+
			"JGTO_z3Wfo5zsqwkxruxwA."+
			"UmVkbW9uZCBXQSA5ODA1Mg."+
			"VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB"+
			"BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT"+
			"-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10"+
			"l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY"+
			"Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr"+
			"ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2"+
			"8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE"+
			"l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U"+
			"zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd"+
			"_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ."+
			"AVO9iT5AV4CzvDJCdhSFlQ";

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWEKeySelector(new JWEKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWEKeys(JWEHeader header, SimpleSecurityContext context) {
				return new LinkedList<>(); // no candidates
			}
		});

		try {
			processor.process(jwt, null);
		} catch (BadJOSEException e) {
			assertEquals("Encrypted JWT rejected: Another algorithm expected, or no matching key(s) found", e.getMessage());
		}
	}


	public void testNoJWSKeySelector()
		throws Exception {

		String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"+
			"."+
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"+
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"+
			"."+
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		try {
			processor.process(jws, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: No JWS key selector is configured", e.getMessage());
		}
	}


	public void testNoJWSFactory()
		throws Exception {

		String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"+
			"."+
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"+
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"+
			"."+
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				Key key = new SecretKeySpec(new Base64URL("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow").decode(), "HMAC");
				return Collections.singletonList(key);
			}
		});

		processor.setJWSVerifierFactory(null);

		try {
			processor.process(jws, null);
			fail();
		} catch (JOSEException e) {
			assertEquals("No JWS verifier is configured", e.getMessage());
		}
	}


	public void testNoJWEKeySelector()
		throws Exception {

		String jwe = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU"+
			"In0."+
			"g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M"+
			"qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE"+
			"b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh"+
			"DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D"+
			"YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq"+
			"JGTO_z3Wfo5zsqwkxruxwA."+
			"UmVkbW9uZCBXQSA5ODA1Mg."+
			"VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB"+
			"BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT"+
			"-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10"+
			"l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY"+
			"Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr"+
			"ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2"+
			"8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE"+
			"l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U"+
			"zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd"+
			"_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ."+
			"AVO9iT5AV4CzvDJCdhSFlQ";

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		try {
			processor.process(jwe, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Encrypted JWT rejected: No JWE key selector is configured", e.getMessage());
		}
	}


	public void testNoJWEFactory()
		throws Exception {

		String jwe = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU"+
			"In0."+
			"g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M"+
			"qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE"+
			"b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh"+
			"DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D"+
			"YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq"+
			"JGTO_z3Wfo5zsqwkxruxwA."+
			"UmVkbW9uZCBXQSA5ODA1Mg."+
			"VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB"+
			"BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT"+
			"-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10"+
			"l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY"+
			"Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr"+
			"ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2"+
			"8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE"+
			"l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U"+
			"zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd"+
			"_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ."+
			"AVO9iT5AV4CzvDJCdhSFlQ";

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWEKeySelector(new JWEKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWEKeys(JWEHeader header, SimpleSecurityContext context) {
				// {"alg":"RSA1_5","enc":"A128CBC-HS256","cty":"JWT"}
				if (header.getAlgorithm().equals(JWEAlgorithm.RSA1_5) && header.getEncryptionMethod().equals(EncryptionMethod.A128CBC_HS256)) {

					String jwk = "{\"kty\":\"RSA\"," +
						"\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl" +
						"UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre" +
						"cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_" +
						"7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI" +
						"Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU" +
						"7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\"," +
						"\"e\":\"AQAB\"," +
						"\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq" +
						"1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry" +
						"nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_" +
						"0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj" +
						"-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj" +
						"T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\"," +
						"\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68" +
						"ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP" +
						"krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\"," +
						"\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y" +
						"BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN" +
						"-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\"," +
						"\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv" +
						"ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra" +
						"Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\"," +
						"\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff" +
						"7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_" +
						"odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\"," +
						"\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC" +
						"tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ" +
						"B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\"" +
						"}";

					try {
						Key rsaPrivateKey = RSAKey.parse(jwk).toRSAPrivateKey();
						return Collections.singletonList(rsaPrivateKey);

					} catch (Exception e) {
						fail(e.getMessage());
					}
				}

				return null;
			}
		});

		processor.setJWEDecrypterFactory(null);

		try {
			processor.process(jwe, null);
			fail();
		} catch (JOSEException e) {
			assertEquals("No JWE decrypter is configured", e.getMessage());
		}
	}


	public void testJWTExpired()
		throws Exception {

		final Date now = new Date();
		final Date yesterday = new Date(now.getTime() - 24*60*60*1000);

		JWTClaimsSet claims = new JWTClaimsSet.Builder()
			.issuer("https://openid.c2id.com")
			.subject("alice")
			.expirationTime(yesterday)
			.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

		jwt.sign(new MACSigner(key));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				return Collections.singletonList(key);
			}
		});

		try {
			processor.process(jwt.serialize(), null);
		} catch (BadJWTException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}


	public void testJWTBeforeUse()
		throws Exception {

		final Date now = new Date();
		final Date tomorrow = new Date(now.getTime() + 24*60*60*1000);

		JWTClaimsSet claims = new JWTClaimsSet.Builder()
			.issuer("https://openid.c2id.com")
			.subject("alice")
			.notBeforeTime(tomorrow)
			.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

		byte[] keyBytes = new byte[32];
		new SecureRandom().nextBytes(keyBytes);
		final SecretKey key = new SecretKeySpec(keyBytes, "HMAC");

		jwt.sign(new MACSigner(key));

		ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();

		processor.setJWSKeySelector(new JWSKeySelector<SimpleSecurityContext>() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SimpleSecurityContext context) {
				return Collections.singletonList(key);
			}
		});

		try {
			processor.process(jwt.serialize(), null);
		} catch (BadJWTException e) {
			assertEquals("JWT before use time", e.getMessage());
		}
	}


	// Example for the WiKi
	public void _testValidateJWTAccessToken()
		throws Exception {

		// The access token to validate, typically submitted with a HTTP header like
		// Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6InMxIn0.eyJzY3A...
		String accessToken =
			"eyJraWQiOiJDWHVwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJib2IiLCJzY" +
				"3AiOlsib3BlbmlkIiwiZW1haWwiXSwiY2xtIjpbIiFCZyJdLCJpc3MiOiJodHRwczpcL1wvZGVtby5jM" +
				"mlkLmNvbVwvYzJpZCIsImV4cCI6MTU3MTMxMjAxOCwiaWF0IjoxNTcxMzExNDE4LCJ1aXAiOnsiZ3Jvd" +
				"XBzIjpbImFkbWluIiwiYXVkaXQiXX0sImp0aSI6ImJBT1BiNWh5TW80IiwiY2lkIjoiMDAwMTIzIn0.Q" +
				"hTAdJK8AbdJJhQarjOz_qvAINQeWJCIYSROVaeRpBfaOrTCUy5gWRf8xrpj1DMibdHwQGPdht3chlAC8" +
				"LGbAorEu0tLLcOwKl4Ql-o30Tdd5QhjNb6PndOY89NbQ1O6cdOZhvV4XB-jUAXi3nDgCw3zvIn2348Va" +
				"2fOAzxUvRs2OGsEDl5d9cmL3e68YqSh7ss12y9oBDyEyz8Py7dtXgt6Tg67n9WlEBG0r4KloGDBdbCCZ" +
				"hlEyURkHaE-3nUcjwd-CEVeqWPO0bsLhwto-80j8BtsfD649GnvaMb9YdbdYhTTs-MkRUQpQIZT0s9oK" +
				"uzKayvZhk0c_0FoSeW7rw";

		// Create a JWT processor for the access tokens
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		
		// Set the required "typ" header "at+jwt" for access tokens
		jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")));

		// The public RSA keys to validate the signatures will be sourced from the
		// OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
		// object caches the retrieved keys to speed up subsequent look-ups and can
		// also handle key-rollover
		JWKSource<SecurityContext> keySource = JWKSourceBuilder.newBuilder(new URL("https://demo.c2id.com/c2id/jwks.json")).build();

		// The expected JWS algorithm of the access tokens (agreed out-of-band)
		JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

		// Configure the JWT processor with a key selector to feed matching public
		// RSA keys sourced from the JWK set URL
		JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
		jwtProcessor.setJWSKeySelector(keySelector);
		
		// Set the required JWT claims for access tokens
		jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
			new JWTClaimsSet.Builder().issuer("https://demo.c2id.com/c2id").build(),
			new HashSet<>(Arrays.asList(JWTClaimNames.SUBJECT, JWTClaimNames.ISSUED_AT, JWTClaimNames.EXPIRATION_TIME, "scp", "cid", JWTClaimNames.JWT_ID))));

		// Process the token
		SecurityContext ctx = null; // optional context parameter, not required here
		JWTClaimsSet claimsSet = jwtProcessor.process(accessToken, ctx);

		// Print out the token claims set
		System.out.println(claimsSet.toJSONObject());
	}


	// Wiki example
	public void testWithEncryption()
		throws Exception {

		byte[] secret = new byte[32];

		// The AES key, obtained from a Java keystore, etc.
		SecretKey secretKey = new SecretKeySpec(secret, "AES");

		// The expected JWE algorithm and method
		JWEAlgorithm expectedJWEAlg = JWEAlgorithm.DIR;
		EncryptionMethod expectedJWEEnc = EncryptionMethod.A128GCM;

		// The JWE key source
		JWKSource<SecurityContext> jweKeySource = new ImmutableSecret<>(secretKey);

		// Configure a key selector to handle the decryption phase
		JWEKeySelector<SecurityContext> jweKeySelector = new JWEDecryptionKeySelector<>(expectedJWEAlg, expectedJWEEnc, jweKeySource);

		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		jwtProcessor.setJWEKeySelector(jweKeySelector);

		jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier() {

			@Override
			public void verify(JWTClaimsSet claimsSet, SecurityContext context)
				throws BadJWTException {

				super.verify(claimsSet, context);

				String issuer = claimsSet.getIssuer();

				if (issuer == null || ! issuer.equals("https://demo.c2id.com/c2id")) {
					throw new BadJWTException("Invalid token issuer");
				}
			}
		});
	}


	// iss178
	public void _testGoogleIDToken()
		throws Exception {

		// ID token from Google
		String token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImU3ZGJmNTI2ZjYzOWMyMTRjZDc3YjM5NmVjYjlkN2Y4MWQ0N2IzODIifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXRfaGFzaCI6ImdYM0ZJYzFxVUZzXy16RTNYYVMtZUEiLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTI4OTY5MTg4OTk2MjY2OTEzNzQiLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJpYXQiOjE0NjMxMzg2NDksImV4cCI6MTQ2MzE0MjI0OX0.GqQ0DPQQ5ixOGGAxcEu_5vqbMS7RyNzLrcn21AEid-61eQU0roq7gMVmCrTLeSghenNKNgFWQeErPe5i-6gxqV0r89dOdXRegpCLPAq7d-acPK_8bw-gOtbEo9Hhzcc56r51FwnZ3IUDgyKB_ZRNdp1LMnBgX--c6vPhy4_ZkVnJvmCzTz6bz-pdZNGFhtKd-xt35qVuyUok9tiGumKh-Tjrov5KPuZI90leRfLpoWDj_ktTClg3VUvXAtvDFhW94xEOS4s8DcvbxP9OrR3zhp4bgLohF-B0OrEqc9pTpYO87HyGJlvT74Re288tGZfCRJFX92BT1M063yt3QPrE8W";
		String jwkUri = "https://www.googleapis.com/oauth2/v3/certs";

		// Set up a JWT processor to parse the tokens and then check their signature
		// and validity time window (bounded by the "iat", "nbf" and "exp" claims)
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

		// The public RSA keys to validate the signatures will be sourced from the
		// OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
		// object caches the retrieved keys to speed up subsequent look-ups and can
		// also gracefully handle key-rollover
		JWKSource<SecurityContext> keySource = JWKSourceBuilder.newBuilder(new URL(jwkUri)).build();

		// The expected JWS algorithm of the access tokens (agreed out-of-band)
		JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

		// Configure the JWT processor with a key selector to feed matching public
		// RSA keys sourced from the JWK set URL
		JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
		jwtProcessor.setJWSKeySelector(keySelector);

		// Process the token
		SecurityContext ctx = null; // optional context parameter, not required here
		JWTClaimsSet claimsSet = jwtProcessor.process(token, ctx);

		// Print out the token claims set
		System.out.println(claimsSet.toJSONObject());
	}
	
	
	@SuppressWarnings("unchecked")
	public void testNestedWithMissingContentTypeHeader()
		throws Exception {
		
		byte[] random32 = new byte[32];
		new SecureRandom().nextBytes(random32);
		final SecretKey hmacKey = new SecretKeySpec(random32, "HmacSha256");
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").build();
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		signedJWT.sign(new MACSigner(hmacKey));
		
		final SecretKey aesKey = new SecretKeySpec(random32, "AES");
		JWEObject jweObject = new JWEObject(
			new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A128GCM),
			new Payload(signedJWT));
		jweObject.encrypt(new AESEncrypter(aesKey));
		
		String jwe = jweObject.serialize();
		
		DefaultJWTProcessor proc = new DefaultJWTProcessor();
		proc.setJWEKeySelector(new JWEKeySelector() {
			@Override
			public List<? extends Key> selectJWEKeys(JWEHeader header, SecurityContext context) throws KeySourceException {
				return Collections.singletonList(aesKey);
			}
		});
		proc.setJWSKeySelector(new JWSKeySelector() {
			@Override
			public List<? extends Key> selectJWSKeys(JWSHeader header, SecurityContext context) throws KeySourceException {
				return Collections.singletonList(hmacKey);
			}
		});
		
		try {
			proc.process(jwe, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Payload of JWE object is not a valid JSON object", e.getMessage());
		}
	}
	
	
	@SuppressWarnings("unchecked")
	public void testNestedWithPlainJWT()
		throws Exception {
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").build();
		PlainJWT plainJWT = new PlainJWT(claimsSet);
		
		byte[] random32 = new byte[32];
		new SecureRandom().nextBytes(random32);
		final SecretKey aesKey = new SecretKeySpec(random32, "AES");
		JWEObject jweObject = new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.A256GCMKW, EncryptionMethod.A128GCM).contentType("JWT").build(),
			new Payload(plainJWT.serialize()));
		jweObject.encrypt(new AESEncrypter(aesKey));
		
		String jwe = jweObject.serialize();
		
		DefaultJWTProcessor proc = new DefaultJWTProcessor();
		proc.setJWEKeySelector(new JWEKeySelector() {
			@Override
			public List<? extends Key> selectJWEKeys(JWEHeader header, SecurityContext context) throws KeySourceException {
				return Collections.singletonList(aesKey);
			}
		});
		
		try {
			proc.process(jwe, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("The payload is not a nested signed JWT", e.getMessage());
		}
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/222/jwe-vulnerability-cannot-force-content
	@SuppressWarnings("unchecked")
	public void testRejectPlainNestedJWT_noCTY()
		throws Exception {
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
			.privateKey(keyPair.getPrivate())
			.keyID("1")
			.build();
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSha256");
		SecretKey hmacKey = keyGenerator.generateKey();
		OctetSequenceKey hmacJWK = new OctetSequenceKey.Builder(hmacKey).build();
		
		DefaultJWTProcessor proc = new DefaultJWTProcessor();
		proc.setJWEKeySelector(new JWEDecryptionKeySelector(
			JWEAlgorithm.RSA_OAEP_256,
			EncryptionMethod.A128GCM,
			new ImmutableJWKSet(new JWKSet(rsaJWK))
		));
		proc.setJWSKeySelector(new JWSVerificationKeySelector(
			JWSAlgorithm.HS256,
			new ImmutableJWKSet(new JWKSet(hmacJWK))
		));
		
		PlainJWT plainJWT = new PlainJWT(new JWTClaimsSet.Builder().subject("alice").build());
		
		JWEObject jweObject = new JWEObject(
			new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM),
			new Payload(plainJWT.serialize()));
		jweObject.encrypt(new RSAEncrypter(rsaJWK));
		
		String jwe = jweObject.serialize();
		
		try {
			proc.process(jwe, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Payload of JWE object is not a valid JSON object", e.getMessage());
		}
	}
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/222/jwe-vulnerability-cannot-force-content
	@SuppressWarnings("unchecked")
	public void testRejectPlainNestedJWT_withCTY()
		throws Exception {
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAKey rsaJWK = new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
			.privateKey(keyPair.getPrivate())
			.keyID("1")
			.build();
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSha256");
		SecretKey hmacKey = keyGenerator.generateKey();
		OctetSequenceKey hmacJWK = new OctetSequenceKey.Builder(hmacKey).build();
		
		DefaultJWTProcessor proc = new DefaultJWTProcessor();
		proc.setJWEKeySelector(new JWEDecryptionKeySelector(
			JWEAlgorithm.RSA_OAEP_256,
			EncryptionMethod.A128GCM,
			new ImmutableJWKSet(new JWKSet(rsaJWK))
		));
		proc.setJWSKeySelector(new JWSVerificationKeySelector(
			JWSAlgorithm.HS256,
			new ImmutableJWKSet(new JWKSet(hmacJWK))
		));
		
		PlainJWT plainJWT = new PlainJWT(new JWTClaimsSet.Builder().subject("alice").build());
		
		JWEObject jweObject = new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
				.contentType("JWT")
				.build(),
			new Payload(plainJWT.serialize()));
		jweObject.encrypt(new RSAEncrypter(rsaJWK));
		
		String jwe = jweObject.serialize();
		
		try {
			proc.process(jwe, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("The payload is not a nested signed JWT", e.getMessage());
		}
	}
	
	
	// issue https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/250/error-on-jwe-decryption-wrong-algorithm
	public void testJCAKeyAlgAccepted()
		throws Exception {
		
		String hostId = "subject";
		
		String sharedSecret = "SharedSecret";
		byte[] salt = new byte[8];
		new SecureRandom().nextBytes(salt);
		
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(sharedSecret.toCharArray(), salt, 65536, 256);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

		// create the JWT
		
		JWSSigner signer = new MACSigner(secretKey.getEncoded());
		
		JWTClaimsSet inputClaimsSet = new JWTClaimsSet.Builder()
			.subject(hostId)
			.expirationTime(new Date(new Date().getTime() + 60*1000L))
			.build();
		
		SignedJWT hmacJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), inputClaimsSet);
		
		hmacJWT.sign(signer);
		
		JWEObject jweObject = new JWEObject(
			new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
				.contentType("JWT")
				.build(),
			new Payload(hmacJWT)
		);
		
		jweObject.encrypt(new DirectEncrypter(secretKey.getEncoded()));
		
		String jweString = jweObject.serialize();

		// parse the JWT
		
		JWT jwt = JWTParser.parse(jweString);
		
		if (!(jwt instanceof EncryptedJWT)) {
			throw new RuntimeException("encrypted JWT required");
		}
		
		ImmutableSecret secret = new ImmutableSecret(secretKey);
		ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
		
		JWEKeySelector jweKeySelector = new JWEDecryptionKeySelector(JWEAlgorithm.DIR, EncryptionMethod.A256GCM, secret);
		jwtProcessor.setJWEKeySelector(jweKeySelector);
		
		JWSKeySelector jwsKeySelector = new JWSVerificationKeySelector(JWSAlgorithm.HS256, secret);
		jwtProcessor.setJWSKeySelector(jwsKeySelector);
		
		JWTClaimsSet outputClaimsSet = jwtProcessor.process((EncryptedJWT) jwt, null);
		
		assertEquals(hostId, outputClaimsSet.getSubject());
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/257/error-on-jwe-decryption-with-aeskw
	public void testJCAKeyAlgAccepted_AES_KW()
		throws Exception {
		
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		gen.init(128);
		OctetSequenceKey aesKey = new OctetSequenceKey.Builder(gen.generateKey().getEncoded()).build();

		// create the JWT
		
		JWTClaimsSet inputClaimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.expirationTime(new Date(new Date().getTime() + 60*1000L))
			.build();
		
		EncryptedJWT encryptedJWT = new EncryptedJWT(
			new JWEHeader.Builder(JWEAlgorithm.A128KW, EncryptionMethod.A256GCM).build(),
			inputClaimsSet
		);
		
		encryptedJWT.encrypt(new AESEncrypter(aesKey));
		
		String jweString = encryptedJWT.serialize();

		JWT jwt = JWTParser.parse(jweString);
		
		if (!(jwt instanceof EncryptedJWT)) {
			throw new RuntimeException("encrypted JWT required");
		}
		
		ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
		
		JWEKeySelector jweKeySelector = new JWEDecryptionKeySelector(JWEAlgorithm.A128KW, EncryptionMethod.A256GCM, new ImmutableJWKSet(new JWKSet(aesKey)));
		jwtProcessor.setJWEKeySelector(jweKeySelector);
		
		JWTClaimsSet outputClaimsSet = jwtProcessor.process((EncryptedJWT) jwt, null);
		
		assertEquals("alice", outputClaimsSet.getSubject());
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/319/restore-defaultjwtprocessorprocess
	public void testPlainOverrideThrowsJOSEException() {
		
		new DefaultJWTProcessor() {
			@Override
			public JWTClaimsSet process(PlainJWT plainJWT, SecurityContext context) throws BadJOSEException, JOSEException {
				try {
					return plainJWT.getJWTClaimsSet();
				} catch (ParseException e) {
					throw new BadJOSEException(e.getMessage());
				}
			}
		};
	}
	
	
	public void testNoJWSTypeVerifier() throws JOSEException {
		
		OctetSequenceKey jwk = new OctetSequenceKeyGenerator(256).generate();
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build());
		signedJWT.sign(new MACSigner(jwk));
		
		DefaultJWTProcessor processor = new DefaultJWTProcessor<>();
		processor.setJWSTypeVerifier(null);
		processor.setJWSKeySelector(new SingleKeyJWSKeySelector(JWSAlgorithm.HS256, jwk.toSecretKey()));
		
		try {
			processor.process(signedJWT, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: No JWS header typ (type) verifier is configured", e.getMessage());
		}
	}
	
	
	public void testNoJWETypeVerifier() throws JOSEException {
		
		final OctetSequenceKey jwk = new OctetSequenceKeyGenerator(256).generate();
		
		EncryptedJWT encryptedJWT = new EncryptedJWT(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM), new JWTClaimsSet.Builder().build());
		encryptedJWT.encrypt(new DirectEncrypter(jwk));
		
		DefaultJWTProcessor processor = new DefaultJWTProcessor();
		processor.setJWETypeVerifier(null);
		processor.setJWEKeySelector(new JWEKeySelector() {
			@Override
			public List<? extends Key> selectJWEKeys(JWEHeader header, SecurityContext context) {
				return Collections.singletonList(jwk.toSecretKey());
			}
		});
		
		try {
			processor.process(encryptedJWT, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Encrypted JWT rejected: No JWE header typ (type) verifier is configured", e.getMessage());
		}
	}
	
	
	public void testCustomJWSTypeVerifier() throws JOSEException, BadJOSEException {
		
		OctetSequenceKey jwk = new OctetSequenceKeyGenerator(256).generate();
		
		DefaultJWTProcessor processor = new DefaultJWTProcessor();
		processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier(new JOSEObjectType("msg")));
		processor.setJWSKeySelector(new SingleKeyJWSKeySelector(JWSAlgorithm.HS256, jwk.toSecretKey()));
		
		// pass
		SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).type(new JOSEObjectType("msg")).build(), new JWTClaimsSet.Builder().build());
		signedJWT.sign(new MACSigner(jwk));
		processor.process(signedJWT, null);
		
		// missing
		signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).build(), new JWTClaimsSet.Builder().build());
		signedJWT.sign(new MACSigner(jwk));
		try {
			processor.process(signedJWT, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Required JOSE header typ (type) parameter is missing", e.getMessage());
		}
		
		// doesn't match
		signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).type(new JOSEObjectType("at+jose")).build(), new JWTClaimsSet.Builder().build());
		signedJWT.sign(new MACSigner(jwk));
		try {
			processor.process(signedJWT, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JOSE header typ (type) at+jose not allowed", e.getMessage());
		}
	}
	
	
	public void testCustomJWETypeVerifier() throws JOSEException, BadJOSEException {
		
		final OctetSequenceKey jwk = new OctetSequenceKeyGenerator(256).generate();
		
		DefaultJWTProcessor processor = new DefaultJWTProcessor();
		processor.setJWETypeVerifier(new DefaultJOSEObjectTypeVerifier(new JOSEObjectType("msg")));
		processor.setJWEKeySelector(new JWEKeySelector() {
			@Override
			public List<? extends Key> selectJWEKeys(JWEHeader header, SecurityContext context) {
				return Collections.singletonList(jwk.toSecretKey());
			}
		});
		
		// pass
		EncryptedJWT jweObject = new EncryptedJWT(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).type(new JOSEObjectType("msg")).build(), new JWTClaimsSet.Builder().build());
		jweObject.encrypt(new DirectEncrypter(jwk));
		processor.process(jweObject, null);
		
		// missing
		jweObject = new EncryptedJWT(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).build(), new JWTClaimsSet.Builder().build());
		jweObject.encrypt(new DirectEncrypter(jwk));
		try {
			processor.process(jweObject, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Required JOSE header typ (type) parameter is missing", e.getMessage());
		}
		
		// doesn't match
		jweObject = new EncryptedJWT(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).type(new JOSEObjectType("at+jose")).build(), new JWTClaimsSet.Builder().build());
		jweObject.encrypt(new DirectEncrypter(jwk));
		try {
			processor.process(jweObject, null);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JOSE header typ (type) at+jose not allowed", e.getMessage());
		}
	}
	
	
	public void testPlainJWT_noJWSTypeVerifier() {
		
		DefaultJWTProcessor processor = new DefaultJWTProcessor();
		processor.setJWSTypeVerifier(null); // none for plain and JWS
		try {
			processor.process(new PlainJWT(new JWTClaimsSet.Builder().build()), null);
			fail();
		} catch (BadJOSEException | JOSEException e) {
			assertEquals("Plain JWT rejected: No JWS header typ (type) verifier is configured", e.getMessage());
		}
	}
}
