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

package com.nimbusds.jose.jwk.source;


import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;


public class ImmutableJWKSetTest extends TestCase {
	

	public void testRun()
		throws Exception {

		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyID("1")
			.generate();

		JWKSet jwkSet = new JWKSet(rsaJWK);

		ImmutableJWKSet<?> immutableJWKSet = new ImmutableJWKSet<>(jwkSet);

		assertEquals(jwkSet, immutableJWKSet.getJWKSet());

		List<JWK> matches = immutableJWKSet.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);
		RSAKey m1 = (RSAKey)matches.get(0);
		assertEquals(rsaJWK.getModulus(), m1.getModulus());
		assertEquals(rsaJWK.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK.getPrivateExponent(), m1.getPrivateExponent());
		assertEquals(1, matches.size());
	}
}
