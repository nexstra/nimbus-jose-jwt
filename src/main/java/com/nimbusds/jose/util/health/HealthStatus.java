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


import net.jcip.annotations.Immutable;


/**
 * Health status.
 */
@Immutable
public class HealthStatus {
	
	private final boolean isHealthy;
	private final long timestamp;
	
	
	/**
	 * Creates a new health status.
	 *
	 * @param isHealthy {@code true} if healthy, else {@code false}.
	 */
	public HealthStatus(final boolean isHealthy) {
		this(isHealthy, System.currentTimeMillis());
	}
	
	
	/**
	 * Creates a new health status.
	 *
	 * @param isHealthy {@code true} if healthy, else {@code false}.
	 * @param timestamp The timestamp, in milliseconds since the Unix
	 *                  epoch.
	 */
	public HealthStatus(final boolean isHealthy, final long timestamp) {
		this.isHealthy = isHealthy;
		this.timestamp = timestamp;
	}
	
	
	/**
	 * Returns the health status.
	 *
	 * @return {@code true} if healthy, else {@code false}.
	 */
	public boolean isHealthy() {
		return isHealthy;
	}
	
	
	/**
	 * Returns the timestamp.
	 *
	 * @return The timestamp, in milliseconds since the Unix epoch.
	 */
	public long getTimestamp() {
		return timestamp;
	}
}