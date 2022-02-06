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

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;

import java.io.Closeable;

/**
 * Provider of a list of Jwk.
 */
public interface JWKSetProvider extends JWKSetHealthProvider, Closeable {

	/**
	 * Returns a list of Jwk.
	 *
	 * @param forceUpdate if true, bypass existing caches and get new values
	 * @return a set of JWK
	 * @throws KeySourceException if no list can be retrieved
	 */
	JWKSet getJWKSet(boolean forceUpdate) throws KeySourceException;

}
