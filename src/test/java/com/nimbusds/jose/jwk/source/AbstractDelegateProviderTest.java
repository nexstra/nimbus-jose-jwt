/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2022, Connect2id Ltd.
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

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.Before;

import java.util.Arrays;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public abstract class AbstractDelegateProviderTest {

	protected static final String KID = "NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg";

	protected JWKSetProvider delegate;

	protected JWK jwk;

	protected JWKSet jwks;

	protected JWKSelector aSelector = new JWKSelector(new JWKMatcher.Builder().keyID("a").build());
	protected JWKSelector bSelector = new JWKSelector(new JWKMatcher.Builder().keyID("b").build());
	protected JWKSelector cSelector = new JWKSelector(new JWKMatcher.Builder().keyID("c").build());

	@Before
	public void setUp() throws Exception {
		delegate = mock(JWKSetProvider.class);
		jwk = mock(JWK.class);
		when(jwk.getKeyID()).thenReturn(KID);
		jwks = new JWKSet(Arrays.asList(jwk));

		when(delegate.getJWKSet(false)).thenReturn(jwks);
	}
	
	protected JWKSourceBuilder builder() {
		return new JWKSourceBuilder(delegate);
	}	
}
