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


public class HealthReportTest extends TestCase {


	public void testMinimalConstructor() {
		
		HealthReport report = new HealthReport(HealthStatus.HEALTHY);
		assertEquals(HealthStatus.HEALTHY, report.getHealthStatus());
		DateUtils.isWithin(DateUtils.fromSecondsSinceEpoch(report.getTimestamp() / 1000L), new Date(), 1);
		assertTrue(report.toString().startsWith("HealthReport{status=HEALTHY, timestamp="));
	}


	public void testFullConstructor_healthy() {
		
		long timestamp = new Date().getTime();
		
		HealthReport report = new HealthReport(HealthStatus.NOT_HEALTHY, timestamp);
		assertEquals(HealthStatus.NOT_HEALTHY, report.getHealthStatus());
		assertEquals(timestamp, report.getTimestamp());
		
		assertEquals("HealthReport{status=NOT_HEALTHY, timestamp=" + timestamp + "}", report.toString());
	}
	
	
	public void testStatusMustNotBeNull() {
		
		try {
			new HealthReport(null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
}
