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

import com.nimbusds.jose.proc.SecurityContext;

public interface JWKSetHealthSource<C extends SecurityContext> {

	/**
	 * Get JWK health.
	 * 
	 * @param refresh true if the source should refresh a missing or bad health
	 *				status before returning.
	 * @param context TODO
	 * @throws UnsupportedOperationException if operation not supported
	 * @return health status.
	 */

	JWKSetHealth getHealth(boolean refresh, C context);

	/**
	 * Check whether getting health is supported
	 *
	 * @return true if this source has support for getting health
	 */

	boolean supportsHealth();
}
