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

public abstract class BaseJWKSetSource implements JWKSetSource {

	protected final JWKSetSource source;

	public BaseJWKSetSource(JWKSetSource source) {
		this.source = source;
	}

	public JWKSetSource getSource() {
		return source;
	}

	@Override
	public JWKSetHealth getHealth(boolean refresh) {
		return source.getHealth(refresh);
	}
	
	@Override
	public void close() throws IOException {
		source.close();
	}

	@Override
	public boolean supportsHealth() {
		return source.supportsHealth();
	}
	
}
