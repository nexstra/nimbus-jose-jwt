package com.nimbusds.jose.mint;


import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

public class DefaultJWSMinterTest extends TestCase {
	public void testConstructor() {

		final ConfigurableJWSMinter<SecurityContext> minter = new DefaultJWSMinter<>();

		assertTrue(minter.getJWSSignerFactory() instanceof DefaultJWSSignerFactory);
		assertNull(minter.getJWKSource());
	}

	public void testMintRoundTrip()
			throws Exception {

		final OctetSequenceKeyGenerator generator = new OctetSequenceKeyGenerator(256);
		final OctetSequenceKey key = generator.generate();
		final JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(key));

		final ConfigurableJWSMinter<SecurityContext> minter = new DefaultJWSMinter<>();
		minter.setJWKSource(jwkSource);

		final JWTClaimsSet claimsIn = new JWTClaimsSet.Builder()
				.issuer("https://openid.c2id.com")
				.subject("alice")
				.build();
		final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
				.type(JOSEObjectType.JWT)
				.build();

		final JWSObject jws = minter.mint(header, claimsIn.toPayload(), null);

		assertEquals(jws.getHeader().getKeyID(), key.getKeyID());
		assertNull(jws.getHeader().getX509CertSHA256Thumbprint());
		assertNull(jws.getHeader().getX509CertURL());
		assertNull(jws.getHeader().getX509CertChain());
		final ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, jwkSource));
		JWTClaimsSet claimsOut = processor.process(jws.serialize(), null);
		assertEquals(claimsOut.getIssuer(), claimsIn.getIssuer());
		assertEquals(claimsOut.getSubject(), claimsIn.getSubject());
	}

	public void testMintRoundTripWhenJWKProvided()
			throws Exception {

		final JWK key = new OctetSequenceKeyGenerator(256)
				.keyID(HeaderParameterNames.KEY_ID).generate();

		final ConfigurableJWSMinter<JWKSecurityContext> minter = new DefaultJWSMinter<>();

		final JWTClaimsSet claimsIn = new JWTClaimsSet.Builder()
				.issuer("https://openid.c2id.com")
				.subject("alice")
				.build();
		final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
				.keyID(key.getKeyID())
				.type(JOSEObjectType.JWT)
				.build();

		final JWSObject jws = minter.mint(header, claimsIn.toPayload(), new JWKSecurityContext(Collections.singletonList(key)));

		final ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		final JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(key));
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, jwkSource));
		final JWTClaimsSet claimsOut = processor.process(jws.serialize(), null);
		assertEquals(claimsOut.getIssuer(), claimsIn.getIssuer());
		assertEquals(claimsOut.getSubject(), claimsIn.getSubject());
	}

	public void testMintRoundTripWhenSelectionOrderCustomized()
			throws Exception {

		final RSAKey rsaKey = (RSAKey) JWK.parseFromPEMEncodedObjects
				(SamplePEMEncodedObjects.RSA_CERT_PEM + "\r\n" + SamplePEMEncodedObjects.RSA_PRIVATE_KEY_PEM);

		final JWK one = new RSAKey.Builder(rsaKey)
				.keyID("one")
				.x509CertSHA256Thumbprint(new Base64URL("abc256"))
				.x509CertURL(URI.create("http://abc.example.com/jwk.json"))
				.build();

		final JWK two = new RSAKey.Builder(rsaKey)
				.keyID("two")
				.x509CertSHA256Thumbprint(new Base64URL("abc256"))
				.x509CertURL(URI.create("http://def.example.com/jwk.json"))
				.build();

		final JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(Arrays.asList(one, two)));
		final JWKSource<SecurityContext> custom = new JWKSource<SecurityContext>() {
			@Override
			public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
				List<JWK> jwks = jwkSource.get(jwkSelector, context);
				if (jwks.isEmpty()) {
					return jwks;
				}
				return Collections.singletonList(jwks.get(jwks.size() - 1));
			}
		};
		final ConfigurableJWSMinter<SecurityContext> minter = new DefaultJWSMinter<>();
		minter.setJWKSource(custom);

		final JWTClaimsSet claimsIn = new JWTClaimsSet.Builder()
				.issuer("https://openid.c2id.com")
				.subject("alice")
				.build();
		final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.x509CertSHA256Thumbprint(new Base64URL("abc256"))
				.type(JOSEObjectType.JWT)
				.build();

		final JWSObject jws = minter.mint(header, claimsIn.toPayload(), null);

		assertEquals(jws.getHeader().getKeyID(), two.getKeyID());
		final ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource));
		final JWTClaimsSet claimsOut = processor.process(jws.serialize(), null);
		assertEquals(claimsOut.getIssuer(), claimsIn.getIssuer());
		assertEquals(claimsOut.getSubject(), claimsIn.getSubject());
	}

	public void testMintWhenJWKContainsX509Detail()
			throws Exception {

		final RSAKey rsaKey = (RSAKey) JWK.parseFromPEMEncodedObjects
				(SamplePEMEncodedObjects.RSA_CERT_PEM + "\r\n" + SamplePEMEncodedObjects.RSA_PRIVATE_KEY_PEM);

		final JWK one = new RSAKey.Builder(rsaKey)
				.keyID("one")
				.x509CertSHA256Thumbprint(new Base64URL("abc256"))
				.x509CertURL(URI.create("http://abc.example.com/jwk.json"))
				.build();

		final JWK two = new RSAKey.Builder(rsaKey)
				.keyID("two")
				.x509CertSHA256Thumbprint(new Base64URL("def256"))
				.x509CertURL(URI.create("http://def.example.com/jwk.json"))
				.build();

		final JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(Arrays.asList(one, two)));
		final ConfigurableJWSMinter<SecurityContext> minter = new DefaultJWSMinter<>();
		minter.setJWKSource(jwkSource);

		final JWTClaimsSet claimsIn = new JWTClaimsSet.Builder()
				.issuer("https://openid.c2id.com")
				.subject("alice")
				.build();
		final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.x509CertSHA256Thumbprint(two.getX509CertSHA256Thumbprint())
				.type(JOSEObjectType.JWT)
				.build();

		final JWSObject jws = minter.mint(header, claimsIn.toPayload(), null);

		assertEquals(jws.getHeader().getKeyID(), two.getKeyID());
		assertEquals(jws.getHeader().getX509CertSHA256Thumbprint(), two.getX509CertSHA256Thumbprint());
		assertEquals(jws.getHeader().getX509CertChain(), two.getX509CertChain());
		assertEquals(jws.getHeader().getX509CertURL(), two.getX509CertURL());
		final ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource));
		final JWTClaimsSet claimsOut = processor.process(jws.serialize(), null);
		assertEquals(claimsOut.getIssuer(), claimsIn.getIssuer());
		assertEquals(claimsOut.getSubject(), claimsIn.getSubject());
	}
}
