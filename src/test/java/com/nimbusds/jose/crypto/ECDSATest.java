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

package com.nimbusds.jose.crypto;


import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.ECParameterTable;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.BigIntegerUtils;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.StandardCharset;


/**
 * Tests the static ECDSA utilities.
 *
 * @version 2022-04-22
 */
public class ECDSATest extends TestCase {


	public void testResolveAlgFromCurve()
		throws JOSEException {

		assertEquals(JWSAlgorithm.ES256, ECDSA.resolveAlgorithm(Curve.P_256));
		assertEquals(JWSAlgorithm.ES256K, ECDSA.resolveAlgorithm(Curve.SECP256K1));
		assertEquals(JWSAlgorithm.ES384, ECDSA.resolveAlgorithm(Curve.P_384));
		assertEquals(JWSAlgorithm.ES512, ECDSA.resolveAlgorithm(Curve.P_521));

		try {
			ECDSA.resolveAlgorithm((Curve)null);

		} catch (JOSEException e) {
			assertEquals("The EC key curve is not supported, must be P-256, P-384 or P-521", e.getMessage());
		}
	}


	public void testResolveAlgFromECKey_P256()
		throws Exception {

		KeyPair keyPair = ECDSARoundTripTest.createECKeyPair(ECDSARoundTripTest.EC256SPEC);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		assertEquals(JWSAlgorithm.ES256, ECDSA.resolveAlgorithm(publicKey));
		assertEquals(JWSAlgorithm.ES256, ECDSA.resolveAlgorithm(privateKey));
	}


	public void testResolveAlgFromECKey_P256K()
		throws Exception {

		KeyPair keyPair = ECDSARoundTripTest.createECKeyPair(ECDSARoundTripTest.EC256KSPEC);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		assertEquals(JWSAlgorithm.ES256K, ECDSA.resolveAlgorithm(publicKey));
		assertEquals(JWSAlgorithm.ES256K, ECDSA.resolveAlgorithm(privateKey));
	}


	public void testResolveAlgFromECKey_P384()
		throws Exception {

		KeyPair keyPair = ECDSARoundTripTest.createECKeyPair(ECDSARoundTripTest.EC384SPEC);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		assertEquals(JWSAlgorithm.ES384, ECDSA.resolveAlgorithm(publicKey));
		assertEquals(JWSAlgorithm.ES384, ECDSA.resolveAlgorithm(privateKey));
	}


	public void testResolveAlgFromECKey_P521()
		throws Exception {

		KeyPair keyPair = ECDSARoundTripTest.createECKeyPair(ECDSARoundTripTest.EC512SPEC);
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

		assertEquals(JWSAlgorithm.ES512, ECDSA.resolveAlgorithm(publicKey));
		assertEquals(JWSAlgorithm.ES512, ECDSA.resolveAlgorithm(privateKey));
	}
	
	
	public void test_default_JCE_for_CVE_2022_21449__zeroSignature() throws Exception {
		
		KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
		
		byte[] blankSignature = new byte[64];
		
		Signature signature = Signature.getInstance("SHA256WithECDSAInP1363Format");
		
		signature.initVerify(keyPair.getPublic());
		signature.update("Hello, World".getBytes());
		boolean verify = signature.verify(blankSignature);
		assertFalse("Your Java runtime is vulnerable to CVE-2022-21449 - Upgrade to a patched Java version!!!", verify);
	}
	
	
	public void test_CVE_2022_21449__zeroSignature() throws ParseException, JOSEException {
		
		for (JWSAlgorithm jwsAlg: Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {
			
			JWSObject jwsObject = new JWSObject(new JWSHeader(jwsAlg), new Payload("Hello, world"));
			
			String jwsString = new String(jwsObject.getSigningInput(), StandardCharset.UTF_8) +
				"." +
				Base64URL.encode(new byte[ECDSA.getSignatureByteArrayLength(jwsAlg)]);
			
			Curve curve = Curve.forJWSAlgorithm(jwsAlg).iterator().next();
			
			assertFalse(JWSObject.parse(jwsString).verify(new ECDSAVerifier(new ECKeyGenerator(curve).generate().toPublicJWK())));
		}
	}
	
	
	public void test_CVE_2022_21449__r_and_s_equal_N() throws ParseException, JOSEException {
		
		for (JWSAlgorithm jwsAlg: Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {
			
			JWSObject jwsObject = new JWSObject(new JWSHeader(jwsAlg), new Payload("Hello, world"));
			
			Curve curve = Curve.forJWSAlgorithm(jwsAlg).iterator().next();
			
			BigInteger n = ECParameterTable.get(curve).getOrder();
			byte[] nBytes = BigIntegerUtils.toBytesUnsigned(n);
			assertEquals(ECDSA.getSignatureByteArrayLength(jwsAlg) / 2, nBytes.length);
			
			Base64URL signatureB64 = Base64URL.encode(ByteUtils.concat(nBytes, nBytes));
			
			if (JWSAlgorithm.ES256.equals(jwsAlg)) {
				// Validated test vector provided by user
				assertEquals("_____wAAAAD__________7zm-q2nF56E87nKwvxjJVH_____AAAAAP__________vOb6racXnoTzucrC_GMlUQ", signatureB64.toString());
				
			}
			
			String jwsString = new String(jwsObject.getSigningInput(), StandardCharset.UTF_8) +
				"." +
				signatureB64;
			
			assertFalse(JWSObject.parse(jwsString).verify(new ECDSAVerifier(new ECKeyGenerator(curve).generate().toPublicJWK())));
		}
	}
	
	
	public void testIsLegalSignature_zeroFilled() throws JOSEException {
		
		int nMaxArraySize = ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES512);
		
		for (int sigSize=1; sigSize <= nMaxArraySize; sigSize++) {
			
			byte[] sigArray = new byte[sigSize];
			
			for (JWSAlgorithm jwsAlg: Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {
				
				try {
					ECDSA.ensureLegalSignature(sigArray, jwsAlg);
					fail();
				} catch (JOSEException e) {
					assertEquals("Blank signature", e.getMessage());
				}
			}
		}
	}
	
	
	public void testIsLegalSignature_unsupportedJWSAlg() {
		
		List<JWSAlgorithm> jwsAlgorithmList = new LinkedList<>();
		jwsAlgorithmList.addAll(JWSAlgorithm.Family.RSA);
		jwsAlgorithmList.add(JWSAlgorithm.EdDSA);
		
		for (JWSAlgorithm jwsAlg: jwsAlgorithmList) {
			
			byte[] sigArray = new byte[32]; // some 1s filled array
			Arrays.fill(sigArray, (byte)1);
			
			try {
				ECDSA.ensureLegalSignature(sigArray, jwsAlg);
				fail();
			} catch (JOSEException e) {
				assertEquals("Unsupported JWS algorithm: " + jwsAlg, e.getMessage());
			}
		}
	}
	
	
	public void testIsLegalSignature_illegalSignatureLength() throws JOSEException {
		
		ECKey ecJWK = new ECKeyGenerator(Curve.P_384).generate();
		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.ES384), new Payload("Hello, world!"));
		jwsObject.sign(new ECDSASigner(ecJWK));
		
		try {
			ECDSA.ensureLegalSignature(jwsObject.getSignature().decode(), JWSAlgorithm.ES256);
			fail();
		} catch (JOSEException e) {
			assertEquals("Illegal signature length", e.getMessage());
		}
		
		try {
			ECDSA.ensureLegalSignature(jwsObject.getSignature().decode(), JWSAlgorithm.ES512);
			fail();
		} catch (JOSEException e) {
			assertEquals("Illegal signature length", e.getMessage());
		}
	}
	
	
	public void testIsLegalSignature_rZero() throws JOSEException {
		
		for (JWSAlgorithm jwsAlg: Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {
			
			int sigLength = ECDSA.getSignatureByteArrayLength(jwsAlg);
			
			byte[] rBytes = new byte[sigLength / 2];
			Arrays.fill(rBytes, (byte)1);
			byte[] sBytes = new byte[sigLength / 2];
			
			byte[] sig = ByteUtils.concat(rBytes, sBytes);
			try {
				ECDSA.ensureLegalSignature(sig, jwsAlg);
				fail();
			} catch (JOSEException e) {
				assertEquals("S and R must not be 0", e.getMessage());
			}
		}
	}
	
	
	public void testIsLegalSignature_sZero() throws JOSEException {
		
		for (JWSAlgorithm jwsAlg: Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {
			
			int sigLength = ECDSA.getSignatureByteArrayLength(jwsAlg);
			
			byte[] rBytes = new byte[sigLength / 2];
			byte[] sBytes = new byte[sigLength / 2];
			Arrays.fill(sBytes, (byte)1);
			
			byte[] sig = ByteUtils.concat(rBytes, sBytes);
			try {
				ECDSA.ensureLegalSignature(sig, jwsAlg);
				fail();
			} catch (JOSEException e) {
				assertEquals("S and R must not be 0", e.getMessage());
			}
		}
	}
	
	
	public void testIsLegalSignature_rEqualsN() throws JOSEException {
		
		for (JWSAlgorithm jwsAlg: Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {
			
			Curve curve = Curve.forJWSAlgorithm(jwsAlg).iterator().next();
			BigInteger n = ECParameterTable.get(curve).getOrder();
			
			int sigLength = ECDSA.getSignatureByteArrayLength(jwsAlg);
			
			byte[] rBytes = BigIntegerUtils.toBytesUnsigned(n);
			byte[] sBytes = new byte[sigLength / 2];
			Arrays.fill(sBytes, (byte)1);
			
			byte[] sig = ByteUtils.concat(rBytes, sBytes);
			assertEquals(sigLength, sig.length);
			
			try {
				ECDSA.ensureLegalSignature(sig, jwsAlg);
				fail();
			} catch (JOSEException e) {
				assertEquals("S and R must not exceed N", e.getMessage());
			}
		}
	}
	
	
	public void testIsLegalSignature_sEqualsN() throws JOSEException {
		
		for (JWSAlgorithm jwsAlg: Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)) {
			
			Curve curve = Curve.forJWSAlgorithm(jwsAlg).iterator().next();
			BigInteger n = ECParameterTable.get(curve).getOrder();
			
			int sigLength = ECDSA.getSignatureByteArrayLength(jwsAlg);
			
			byte[] rBytes = new byte[sigLength / 2];
			Arrays.fill(rBytes, (byte)1);
			byte[] sBytes = BigIntegerUtils.toBytesUnsigned(n);
			
			byte[] sig = ByteUtils.concat(rBytes, sBytes);
			assertEquals(sigLength, sig.length);
			
			try {
				ECDSA.ensureLegalSignature(sig, jwsAlg);
				fail();
			} catch (JOSEException e) {
				assertEquals("S and R must not exceed N", e.getMessage());
			}
		}
	}
}
