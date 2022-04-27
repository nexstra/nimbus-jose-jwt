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

package com.nimbusds.jose.crypto;


import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;


/**
 * RSA-OAEP-256, RSA-OAEP-384, RSA-OAEP-512
 */
public class RSA_OAEP_SHA2_Test extends TestCase {
	
	
	private static final List<JWEAlgorithm> JWE_ALGORITHMS_TO_TEST =
		Collections.unmodifiableList(
			Arrays.asList(
				JWEAlgorithm.RSA_OAEP_256,
				JWEAlgorithm.RSA_OAEP_384,
				JWEAlgorithm.RSA_OAEP_512)
		);
	
	
	private static final List<EncryptionMethod> ENCRYPTION_METHODS_TO_TEST =
		Collections.unmodifiableList(
			Arrays.asList(
				EncryptionMethod.A128CBC_HS256,
				EncryptionMethod.A192CBC_HS384,
				EncryptionMethod.A256CBC_HS512,
				EncryptionMethod.A128GCM,
				EncryptionMethod.A192GCM,
				EncryptionMethod.A256GCM,
				EncryptionMethod.A128CBC_HS256_DEPRECATED,
				EncryptionMethod.A256CBC_HS512_DEPRECATED
			)
		);
	
	
	public void testRoundTrip_JavaKeys()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(4096);
		KeyPair kp = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
		
		for (JWEAlgorithm jweAlg: JWE_ALGORITHMS_TO_TEST) {
			
			for (Provider provider : Arrays.asList(null, BouncyCastleProviderSingleton.getInstance())) {
				
				RSAEncrypter encrypter = new RSAEncrypter(publicKey);
				
				RSADecrypter decrypter = new RSADecrypter(privateKey);
				
				if (provider != null) {
					encrypter.getJCAContext().setProvider(provider);
					decrypter.getJCAContext().setProvider(provider);
				}
				
				for (EncryptionMethod enc : ENCRYPTION_METHODS_TO_TEST) {
					
					JWEObject jwe = new JWEObject(
						new JWEHeader(jweAlg, enc),
						new Payload("Hello, world!"));
					
					assertEquals(JWEObject.State.UNENCRYPTED, jwe.getState());
					
					jwe.encrypt(encrypter);
					
					assertEquals(JWEObject.State.ENCRYPTED, jwe.getState());
					
					String jweString = jwe.serialize();
					
					jwe = JWEObject.parse(jweString);
					
					jwe.decrypt(decrypter);
					
					assertEquals(JWEObject.State.DECRYPTED, jwe.getState());
					
					assertEquals("Hello, world!", jwe.getPayload().toString());
				}
			}
		}
	}
	
	
	public void testRoundTrip_JWK()
		throws Exception {
		
		RSAKey privateJWK = new RSAKeyGenerator(4096)
			.keyUse(KeyUse.ENCRYPTION)
			.generate();
		RSAKey publicJWK = privateJWK.toPublicJWK();
		
		for (JWEAlgorithm jweAlg: JWE_ALGORITHMS_TO_TEST) {
			
			for (Provider provider : Arrays.asList(null, BouncyCastleProviderSingleton.getInstance())) {
				
				RSAEncrypter encrypter = new RSAEncrypter(publicJWK);
				
				RSADecrypter decrypter = new RSADecrypter(privateJWK);
				
				if (provider != null) {
					encrypter.getJCAContext().setProvider(provider);
					decrypter.getJCAContext().setProvider(provider);
				}
				
				for (EncryptionMethod enc : ENCRYPTION_METHODS_TO_TEST) {
					
					JWEObject jwe = new JWEObject(
						new JWEHeader(jweAlg, enc),
						new Payload("Hello, world!"));
					
					assertEquals(JWEObject.State.UNENCRYPTED, jwe.getState());
					
					jwe.encrypt(encrypter);
					
					assertEquals(JWEObject.State.ENCRYPTED, jwe.getState());
					
					String jweString = jwe.serialize();
					
					jwe = JWEObject.parse(jweString);
					
					jwe.decrypt(decrypter);
					
					assertEquals(JWEObject.State.DECRYPTED, jwe.getState());
					
					assertEquals("Hello, world!", jwe.getPayload().toString());
				}
			}
		}
	}
	
	
	public void testRoundTripWithCekSpecified()
		throws Exception {
		
		// Generate RSA key pair
		KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
		rsaGen.initialize(4096);
		KeyPair rsaKeyPair = rsaGen.generateKeyPair();
		RSAPublicKey rsaPublicKey = (RSAPublicKey)rsaKeyPair.getPublic();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)rsaKeyPair.getPrivate();
		
		// Generate AES content encryption key
		EncryptionMethod encryptionMethod = EncryptionMethod.A128CBC_HS256;
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(EncryptionMethod.A128CBC_HS256.cekBitLength());
		SecretKey cek = keyGenerator.generateKey();
		
		for (JWEAlgorithm jweAlg: JWE_ALGORITHMS_TO_TEST) {
			
			//encrypt JWE with rsa public key + specified AES key
			JWEObject jwe = new JWEObject(
				new JWEHeader(jweAlg, encryptionMethod),
				new Payload("Hello, world!"));
			jwe.encrypt(new RSAEncrypter(rsaPublicKey, cek));
			assertEquals(JWEObject.State.ENCRYPTED, jwe.getState());
			String jweString = jwe.serialize();
			
			//decrypt JWE with RSA private key
			jwe = JWEObject.parse(jweString);
			jwe.decrypt(new RSADecrypter(rsaPrivateKey));
			assertEquals(JWEObject.State.DECRYPTED, jwe.getState());
			assertEquals("Hello, world!", jwe.getPayload().toString());
			
			//decrypt JWE with CEK directly
			jwe = JWEObject.parse(jweString);
			jwe.decrypt(new DirectDecrypter(cek, true));
			assertEquals(JWEObject.State.DECRYPTED, jwe.getState());
			assertEquals("Hello, world!", jwe.getPayload().toString());
		}
	}
	
	public void testRoundTripWithCekSpecified_lengthDoesntMatchEnc()
		throws Exception {
		
		// Generate RSA key pair
		KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
		rsaGen.initialize(4096);
		KeyPair rsaKeyPair = rsaGen.generateKeyPair();
		RSAPublicKey rsaPublicKey = (RSAPublicKey)rsaKeyPair.getPublic();
		
		// Generate AES content encryption key
		EncryptionMethod encryptionMethod = EncryptionMethod.A128CBC_HS256;
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey cek = keyGenerator.generateKey();
		
		for (JWEAlgorithm jweAlg: JWE_ALGORITHMS_TO_TEST) {
			
			//encrypt JWE with rsa public key + specified AES key
			JWEObject jwe = new JWEObject(
				new JWEHeader(jweAlg, encryptionMethod),
				new Payload("Hello, world!"));
			
			try {
				jwe.encrypt(new RSAEncrypter(rsaPublicKey, cek));
				fail();
			} catch (KeyLengthException e) {
				assertEquals("The Content Encryption Key (CEK) length for A128CBC-HS256 must be 256 bits", e.getMessage());
			}
		}
	}
	
	
	public void testRSAKeyTooShortToEncryptCEK()
		throws Exception {
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);
		KeyPair kp = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		
		for (JWEAlgorithm jweAlg: JWE_ALGORITHMS_TO_TEST) {
			
			JWEObject jwe = new JWEObject(
				new JWEHeader(jweAlg, EncryptionMethod.A256CBC_HS512),
				new Payload("Hello, world!"));
			
			try {
				jwe.encrypt(new RSAEncrypter(publicKey));
				fail();
			} catch (JOSEException e) {
				if (JWEAlgorithm.RSA_OAEP_256.equals(jweAlg) || JWEAlgorithm.RSA_OAEP_384.equals(jweAlg)) {
					assertEquals("RSA block size exception: The RSA key is too short, use a longer one", e.getMessage());
					assertTrue(e.getCause() instanceof IllegalBlockSizeException);
				} else {
					assertEquals("Key is too short for encryption using OAEPPadding with SHA-512 and MGF1SHA-512", e.getMessage());
					assertTrue(e.getCause() instanceof InvalidKeyException);
				}
			}
		}
	}
	
	
	/**
	 * RSA OAEP 256 JWE example from Brian Campbell (JOSE4J).
	 */
	public void testJOSE4JExample_RSA_OAEP_256()
		throws Exception {
		
		String jwkString = "{\"kty\":\"RSA\",\"n\":\"2cQJH1f6yF9DcGa8Cmbnhn4LHLs5L6kNb2rxkrNFZArJLRaKvaC3tMCKZ8ZgIpO9bVMPx5UMjJoaf7p9O5BSApVqA2J10fUbdSIomCcDwvGo0eyhty0DILLWTMXzGEVM3BXzuJQoeDkuUCXXcCwA4Msyyd2OHVu-pB2OrGv6fcjHwjINty3UoKm08lCvAevBKHsuA-FFwQII9bycvRx5wRqFUjdMAyiOmLYBHBaJSi11g3HVexMcb29v14PSlVzdGUMN8oboa-zcIyaPrIiczLqAkSXQNdEFHrjsJHfFeNMfOblLM7icKN_tyWujYeItt4kqUIimPn5dHjwgcQYE7w\",\"e\":\"AQAB\",\"d\":\"dyUz3ItVceX1Tv1WqtZMnKA_0jN5gWMcL7ayf5JISAlCssGfnUre2C10TH0UQjbVMIh-nLMnD5KNJw9Qz5MR28oGG932Gq7hm__ZeA34l-OCe4DdpgwhpvVSHOU9MS1RdSUpmPavAcA_X6ikrAHXZSaoHhxzUgrNTpvBYQMfJUv_492fStIseQ9rwAMOpCWOiWMZOQm3KJVTLLunXdKf_UxmzmKXYKYZWke3AWIzUqnOfqIjfDTMunF4UWU0zKlhcsaQNmYMVrJGajD1bJdy_dbUU3LE8sx-bdkUI6oBk-sFtTTVyVdQcetG9kChJ5EnY5R6tt_4_xFG5kxzTo6qaQ\",\"p\":\"7yQmgE60SL7QrXpAJhChLgKnXWi6C8tVx1lA8FTpphpLaCtK-HbgBVHCprC2CfaM1mxFJZahxgFjC9ehuV8OzMNyFs8kekS82EsQGksi8HJPxyR1fU6ATa36ogPG0nNaqm3EDmYyjowhntgBz2OkbFAsTMHTdna-pZBRJa9lm5U\",\"q\":\"6R4dzo9LwHLO73EMQPQsmwXjVOvAS5W6rgQ-BCtMhec_QosAXIVE3AGyfweqZm6rurXCVFykDLwJ30GepLQ8nTlzeV6clx0x70saGGKKVmCsHuVYWwgIRyJTrt4SX29NQDZ_FE52NlO3OhPkj1ExSk_pGMqGRFd26K8g0jJsXXM\",\"dp\":\"VByn-hs0qB2Ncmb8ZycUOgWu7ljmjz1up1ZKU_3ZzJWVDkej7-6H7vcJ-u1OqgRxFv4v9_-aWPWl68VlWbkIkJbx6vniv6qrrXwBZu4klOPwEYBOXsucrzXRYOjpJp5yNl2zRslFYQQC00bwpAxNCdfNLRZDlXhAqCUxlYqyt10\",\"dq\":\"MJFbuGtWZvQEdRJicS3uFSY25LxxRc4eJJ8xpIC44rT5Ew4Otzf0zrlzzM92Cv1HvhCcOiNK8nRCwkbTnJEIh-EuU70IdttYSfilqSruk2x0r8Msk1qrDtbyBF60CToRKC2ycDKgolTyuaDnX4yU7lyTvdyD-L0YQwYpmmFy_k0\",\"qi\":\"vy7XCwZ3jyMGik81TIZDAOQKC8FVUc0TG5KVYfti4tgwzUqFwtuB8Oc1ctCKRbE7uZUPwZh4OsCTLqIvqBQda_kaxOxo5EF7iXj6yHmZ2s8P_Z_u3JLuh-oAT_6kmbLx6CAO0DbtKtxp24Ivc1hDfqSwWORgN1AOrSRCmE3nwxg\"}";
		
		RSAKey jwk = RSAKey.parse(jwkString);
		
		String jweString = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.fL5IL5cMCjjU9G9_ZjsD2XO0HIwTOwbVwulcZVw31_rx2qTcHzbYhIvrvbcVLTfJzn8xbQ3UEL442ZgZ1PcFYKENYePXiEyvYxPN8dmvj_OfLSJDEqR6kvwOb6nghGtxfzdB_VRvFt2eehbCA3gWpiOYHHvSTFdBPGx2KZHQisLz3oZR8EWiZ1woEpHy8a7FoQ2zzuDlZEJQOUrh09b_EJxmcE2jL6wmEtgabyxy3VgWg3GqSPUISlJZV9HThuVJezzktJdpntRDnAPUqjc8IwByGpMleIQcPuBUseRRPr_OsroOJ6eTl5DuFCmBOKb-eNNw5v-GEcVYr1w7X9oXoA.0frdIwx8P8UAzh1s9_PgOA.RAzILH0xfs0yxzML1CzzGExCfE2_wzWKs0FVuXfM8R5H68yTqTbqIqRCp2feAH5GSvluzmztk2_CkGNSjAyoaw.4nMUXOgmgWvM-08tIZ-h5w";
		
		JWEObject jweObject = JWEObject.parse(jweString);
		
		assertEquals(JWEAlgorithm.RSA_OAEP_256, jweObject.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A128CBC_HS256, jweObject.getHeader().getEncryptionMethod());
		
		RSADecrypter decrypter = new RSADecrypter(jwk.toRSAPrivateKey());
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);
		
		assertEquals(JWEObject.State.DECRYPTED, jweObject.getState());
		assertEquals("Well, as of this moment, they're on DOUBLE SECRET PROBATION!", jweObject.getPayload().toString());
	}
	
	
	/**
	 * RSA OAEP 512 JWE example from Brian Campbell (JOSE4J).
	 */
	public void testJOSE4JExample_RSA_OAEP_512()
		throws Exception {
		
		String jwkString = "{\"kty\":\"RSA\",\"n\":\"2cQJH1f6yF9DcGa8Cmbnhn4LHLs5L6kNb2rxkrNFZArJLRaKvaC3tMCKZ8ZgIpO9bVMPx5UMjJoaf7p9O5BSApVqA2J10fUbdSIomCcDwvGo0eyhty0DILLWTMXzGEVM3BXzuJQoeDkuUCXXcCwA4Msyyd2OHVu-pB2OrGv6fcjHwjINty3UoKm08lCvAevBKHsuA-FFwQII9bycvRx5wRqFUjdMAyiOmLYBHBaJSi11g3HVexMcb29v14PSlVzdGUMN8oboa-zcIyaPrIiczLqAkSXQNdEFHrjsJHfFeNMfOblLM7icKN_tyWujYeItt4kqUIimPn5dHjwgcQYE7w\",\"e\":\"AQAB\",\"d\":\"dyUz3ItVceX1Tv1WqtZMnKA_0jN5gWMcL7ayf5JISAlCssGfnUre2C10TH0UQjbVMIh-nLMnD5KNJw9Qz5MR28oGG932Gq7hm__ZeA34l-OCe4DdpgwhpvVSHOU9MS1RdSUpmPavAcA_X6ikrAHXZSaoHhxzUgrNTpvBYQMfJUv_492fStIseQ9rwAMOpCWOiWMZOQm3KJVTLLunXdKf_UxmzmKXYKYZWke3AWIzUqnOfqIjfDTMunF4UWU0zKlhcsaQNmYMVrJGajD1bJdy_dbUU3LE8sx-bdkUI6oBk-sFtTTVyVdQcetG9kChJ5EnY5R6tt_4_xFG5kxzTo6qaQ\",\"p\":\"7yQmgE60SL7QrXpAJhChLgKnXWi6C8tVx1lA8FTpphpLaCtK-HbgBVHCprC2CfaM1mxFJZahxgFjC9ehuV8OzMNyFs8kekS82EsQGksi8HJPxyR1fU6ATa36ogPG0nNaqm3EDmYyjowhntgBz2OkbFAsTMHTdna-pZBRJa9lm5U\",\"q\":\"6R4dzo9LwHLO73EMQPQsmwXjVOvAS5W6rgQ-BCtMhec_QosAXIVE3AGyfweqZm6rurXCVFykDLwJ30GepLQ8nTlzeV6clx0x70saGGKKVmCsHuVYWwgIRyJTrt4SX29NQDZ_FE52NlO3OhPkj1ExSk_pGMqGRFd26K8g0jJsXXM\",\"dp\":\"VByn-hs0qB2Ncmb8ZycUOgWu7ljmjz1up1ZKU_3ZzJWVDkej7-6H7vcJ-u1OqgRxFv4v9_-aWPWl68VlWbkIkJbx6vniv6qrrXwBZu4klOPwEYBOXsucrzXRYOjpJp5yNl2zRslFYQQC00bwpAxNCdfNLRZDlXhAqCUxlYqyt10\",\"dq\":\"MJFbuGtWZvQEdRJicS3uFSY25LxxRc4eJJ8xpIC44rT5Ew4Otzf0zrlzzM92Cv1HvhCcOiNK8nRCwkbTnJEIh-EuU70IdttYSfilqSruk2x0r8Msk1qrDtbyBF60CToRKC2ycDKgolTyuaDnX4yU7lyTvdyD-L0YQwYpmmFy_k0\",\"qi\":\"vy7XCwZ3jyMGik81TIZDAOQKC8FVUc0TG5KVYfti4tgwzUqFwtuB8Oc1ctCKRbE7uZUPwZh4OsCTLqIvqBQda_kaxOxo5EF7iXj6yHmZ2s8P_Z_u3JLuh-oAT_6kmbLx6CAO0DbtKtxp24Ivc1hDfqSwWORgN1AOrSRCmE3nwxg\"}";
		
		RSAKey jwk = RSAKey.parse(jwkString);
		
		String jweString = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtNTEyIn0.HH3z1TA5Ea8bKmt-yUlz3AqhsucX4eUPERH9s1E9boQqDusfjG4L2PqhDHR0YMmmKN7U6qhbwN6HbcB8cxkel4jeV3yyy49Kr4kLQfvPa4o2EAfAjnc9c6pqoRW1ZW2yhDtrA15P_HNERaAXMcW5v3X5zBDAJ7PmQ98aoZd9a7K_u_zQ4GrkE-9M1hPWcQzr9D9kMdZq4I-jMniISzuMrSddXh_t2-HbFyiegYFJUAanCFw5g7_y7iv2Sd7AqCLZwqH42WTfJkmLLUAES-9UhUiiNP9NIzPOkwurxSrsNP0jeISYx7ZuiQKj8gU-7w29iK2fdi1ugBxaCHK4dR2Azg.ovfoQ3CzQwfa4FA2.ieOzLwMEH-ZM8PV70tcT2GWGaEENVScYzvuR0S3cfIO-hF4vvfqofVcA3iuodokfCWSWWnGDGKsc4I1N.ztlTWtSndHEHQ2_Ya37tNQ";
		
		JWEObject jweObject = JWEObject.parse(jweString);
		
		assertEquals(JWEAlgorithm.RSA_OAEP_512, jweObject.getHeader().getAlgorithm());
		assertEquals(EncryptionMethod.A256GCM, jweObject.getHeader().getEncryptionMethod());
		
		RSADecrypter decrypter = new RSADecrypter(jwk.toRSAPrivateKey());
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);
		
		assertEquals(JWEObject.State.DECRYPTED, jweObject.getState());
		assertEquals("Well, as of this moment, they're on DOUBLE SECRET PROBATION!", jweObject.getPayload().toString());
	}
}
