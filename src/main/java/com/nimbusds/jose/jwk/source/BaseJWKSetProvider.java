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

import java.io.IOException;

public abstract class BaseJWKSetProvider implements JWKSetProvider {

	protected final JWKSetProvider provider;

	public BaseJWKSetProvider(JWKSetProvider provider) {
		this.provider = provider;
	}

	public JWKSetProvider getProvider() {
		return provider;
	}

	@Override
	public JWKSetHealth getHealth(boolean refresh) {
		return provider.getHealth(refresh);
	}
	
	@Override
	public void close() throws IOException {
		provider.close();
	}

	@Override
	public boolean supportsHealth() {
		return provider.supportsHealth();
	}
}
