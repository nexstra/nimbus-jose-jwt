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

package com.nimbusds.jose.proc;


import java.net.URL;
import java.security.Key;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;

/**
 * A {@link JWSKeySelector} that expects an algorithm from a specified
 * algorithm family.
 *
 * @author Josh Cummings
 * @since 2019-07-12
 */
public class JWSAlgorithmFamilyJWSKeySelector<C extends SecurityContext> extends AbstractJWKSelectorWithSource<C> implements JWSKeySelector<C> {
	
	
	private final Map<JWSAlgorithm, JWSKeySelector<C>> selectors = new HashMap<>();

	
	/**
	 * Creates a {@link JWSKeySelector} that matches any algorithm from the
	 * given {@link JWSAlgorithm.Family}.
	 *
	 * @param jwsAlgFamily The {@link JWSAlgorithm.Family} to use.
	 * @param jwkSource    The {@link JWKSource} from which to draw the set
	 *                     of {@link JWK}s.
	 */
	public JWSAlgorithmFamilyJWSKeySelector(final JWSAlgorithm.Family jwsAlgFamily, final JWKSource<C> jwkSource) {
		super(jwkSource);
		if (jwsAlgFamily == null) {
			throw new IllegalArgumentException("JWS algorithm family must not be null");
		}
		for (JWSAlgorithm jwsAlg : jwsAlgFamily) {
			this.selectors.put(jwsAlg, new JWSVerificationKeySelector<>(jwsAlg, jwkSource));
		}
	}

	
	@Override
	public List<? extends Key> selectJWSKeys(final JWSHeader header, final C context)
		throws KeySourceException {
		
		JWSKeySelector<C> selector = this.selectors.get(header.getAlgorithm());
		if (selector == null) {
			return Collections.emptyList();
		}
		return selector.selectJWSKeys(header, context);
	}

	
	/**
	 * Queries the given JWK Set {@link URL} for keys, creating a
	 * {@link JWSAlgorithmFamilyJWSKeySelector} based on the RSA or EC key
	 * type, whichever comes back first.
	 *
	 * @param jwkSetURL The JWK Set {@link URL} to query.
	 * @param <C>       The {@link SecurityContext}
	 *
	 * @return An instance of {@link JWSAlgorithmFamilyJWSKeySelector}.
	 *
	 * @throws KeySourceException if the JWKs cannot be retrieved or no RSA
	 *                            or EC public JWKs are found.
	 */
	public static <C extends SecurityContext> JWSAlgorithmFamilyJWSKeySelector<C> fromJWKSetURL(final URL jwkSetURL)
		throws KeySourceException {

		JWKSource<C> jwkSource = new RemoteJWKSet<>(jwkSetURL);
		return fromJWKSource(jwkSource);
	}
	

	/**
	 * Queries the given {@link JWKSource} for keys, creating a
	 * {@link JWSAlgorithmFamilyJWSKeySelector} based on the RSA or EC key
	 * type, whichever comes back first.
	 *
	 * @param jwkSource The {@link JWKSource}.
	 * @param <C>       The {@link SecurityContext}.
	 *
	 * @return An instance of {@link JWSAlgorithmFamilyJWSKeySelector}.
	 *
	 * @throws KeySourceException If the JWKs cannot be retrieved or no
	 *                            RSA or EC public JWKs are found.
	 */
	public static <C extends SecurityContext> JWSAlgorithmFamilyJWSKeySelector<C> fromJWKSource(final JWKSource<C> jwkSource)
		throws KeySourceException {
		
		JWKMatcher jwkMatcher = new JWKMatcher.Builder()
				.publicOnly(true)
				.keyUses(KeyUse.SIGNATURE, null) // use=sig is optional
				.keyTypes(KeyType.RSA, KeyType.EC)
				.build();
		List<? extends JWK> jwks = jwkSource.get(new JWKSelector(jwkMatcher), null);
		for (JWK jwk : jwks) {
			if (KeyType.RSA.equals(jwk.getKeyType())) {
				return new JWSAlgorithmFamilyJWSKeySelector<>(JWSAlgorithm.Family.RSA, jwkSource);
			}
			if (KeyType.EC.equals(jwk.getKeyType())) {
				return new JWSAlgorithmFamilyJWSKeySelector<>(JWSAlgorithm.Family.EC, jwkSource);
			}
		}
		throw new KeySourceException("Couldn't retrieve JWKs");
	}
}
