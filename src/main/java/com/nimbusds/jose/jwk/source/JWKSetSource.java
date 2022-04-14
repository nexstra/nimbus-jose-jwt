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


import java.io.Closeable;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.health.HealthStatusReporting;


/**
 * JSON Web Key (JWK) set source with optional health status reporting.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-09
 */
public interface JWKSetSource<C extends SecurityContext> extends HealthStatusReporting<C>, Closeable {

	
	/**
	 * Gets the JWK set.
	 *
	 * @param forceReload If {@code true} and caching is present forces a
	 *                    reloading of the JWK set when older than the
	 *                    current time argument.
	 * @param currentTime The current time, in milliseconds since the Unix
	 *                    epoch.
	 * @param context     Optional context, {@code null} if not required.
	 *
	 * @return The JWK set.
	 *
	 * @throws KeySourceException If JWK set retrieval failed.
	 */
	JWKSet getJWKSet(final boolean forceReload, final long currentTime, final C context)
		throws KeySourceException;
}
