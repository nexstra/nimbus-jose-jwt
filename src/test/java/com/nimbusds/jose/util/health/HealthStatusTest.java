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


import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jwt.util.DateUtils;


public class HealthStatusTest extends TestCase {


	public void testMinimalConstructor_healthy() {
		
		HealthStatus status = new HealthStatus(true);
		assertTrue(status.isHealthy());
		DateUtils.isWithin(DateUtils.fromSecondsSinceEpoch(status.getTimestamp() / 1000L), new Date(), 1);
	}


	public void testMinimalConstructor_notHealthy() {
		
		HealthStatus status = new HealthStatus(false);
		assertFalse(status.isHealthy());
		DateUtils.isWithin(DateUtils.fromSecondsSinceEpoch(status.getTimestamp() / 1000L), new Date(), 1);
	}


	public void testFullConstructor_healthy() {
		
		long timestamp = new Date().getTime();
		
		HealthStatus status = new HealthStatus(true, timestamp);
		assertTrue(status.isHealthy());
		assertEquals(timestamp, status.getTimestamp());
	}


	public void testFullConstructor_notHealthy() {
		
		long timestamp = new Date().getTime();
		
		HealthStatus status = new HealthStatus(false, timestamp);
		assertFalse(status.isHealthy());
		assertEquals(timestamp, status.getTimestamp());
	}
}
