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

import com.nimbusds.jose.proc.SecurityContext;

public abstract class BaseJWKSetSource<C extends SecurityContext> implements JWKSetSource<C> {

	protected final JWKSetSource<C> source;

	public BaseJWKSetSource(JWKSetSource<C> source) {
		this.source = source;
	}

	public JWKSetSource<C> getSource() {
		return source;
	}

	@Override
	public JWKSetHealth getHealth(boolean refresh, C context) {
		return source.getHealth(refresh, context);
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
