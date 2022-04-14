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


import java.util.Objects;

import net.jcip.annotations.Immutable;


/**
 * Health report.
 */
@Immutable
public class HealthReport {
	
	
	/**
	 * The health status.
	 */
	private final HealthStatus status;
	
	
	/**
	 * The report timestamp.
	 */
	private final long timestamp;
	
	
	/**
	 * Creates a new health report.
	 *
	 * @param status The health status. Must not be {@code null}.
	 */
	public HealthReport(final HealthStatus status) {
		this(status, System.currentTimeMillis());
	}
	
	
	/**
	 * Creates a new health report.
	 *
	 * @param status    The health status. Must not be {@code null}.
	 * @param timestamp The timestamp, in milliseconds since the Unix
	 *                  epoch.
	 */
	public HealthReport(final HealthStatus status, final long timestamp) {
		Objects.requireNonNull(status);
		this.status = status;
		this.timestamp = timestamp;
	}
	
	
	/**
	 * Returns the health status.
	 *
	 * @return The health status.
	 */
	public HealthStatus getHealthStatus() {
		return status;
	}
	
	
	/**
	 * Returns the timestamp.
	 *
	 * @return The timestamp, in milliseconds since the Unix epoch.
	 */
	public long getTimestamp() {
		return timestamp;
	}
	
	
	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder("HealthReport{");
		sb.append("status=").append(status);
		sb.append(", timestamp=").append(timestamp);
		sb.append('}');
		return sb.toString();
	}
}