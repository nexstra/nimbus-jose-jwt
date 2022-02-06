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

public interface JWKSetHealthProvider {

	/**
	 * Get JWK health.
	 * 
	 * @param refresh true if the provider should refresh a missing or bad health
	 *				status before returning.
	 * @throws JWKSetHealthNotSupportedException if operation not supported
	 * @return health status.
	 */

	JWKSetHealth getHealth(boolean refresh);

	/**
	 * Check whether getting health is supported
	 *
	 * @return true if this provider has support for getting health
	 */

	boolean supportsHealth();
}
