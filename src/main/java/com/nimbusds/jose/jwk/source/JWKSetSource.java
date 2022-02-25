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
 * Source of a set of JWK.
 */
public interface JWKSetSource extends JWKSetHealthSource, Closeable {

	/**
	 * Get a set of JWKs.
	 *
	 * @param currentTime current time in milliseconds since 1970. 
	 * @param forceUpdate if true, bypass existing caches if 
	 *        the current cache is older than the passed currentTime parameter 
	 * @return a set of JWKs
	 * @throws KeySourceException if no list can be retrieved
	 */
	JWKSet getJWKSet(long currentTime, boolean forceUpdate) throws KeySourceException;

}
