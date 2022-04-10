/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.util.health;

import com.nimbusds.jose.proc.SecurityContext;


/**
 * Health status reporting.
 */
public interface HealthStatusReporting <C extends SecurityContext> {

	
	/**
	 * Reports the health status if {@linkplain #supportsHealthStatus()
	 * reporting is supported}.
	 * 
	 * @param refresh {@code true} to refresh the health status before
	 *                returning the report.
	 * @param context The context, {@code null} if not specified.
	 *
	 * @throws UnsupportedOperationException If reporting is not supported.
	 *
	 * @return The health status, {@code null} if unknown.
	 */
	HealthStatus reportHealthStatus(final boolean refresh, final C context);

	
	/**
	 * Returns {@code true} if reporting of health status is supported.
	 *
	 * @return {@code true} if reporting of health status is supported,
	 *         else {@code false}.
	 */
	boolean supportsHealthStatus();
}
