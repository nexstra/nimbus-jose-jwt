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

package com.nimbusds.jose.jwk.source;


import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jwt.util.DateUtils;


public class JWKSetWithTimestampTest extends TestCase {
	
	
	static final JWKSet SAMPLE_JWK_SET;
	
	static {
		try {
			SAMPLE_JWK_SET = new JWKSet(new OctetSequenceKeyGenerator(256)
				.generate());
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}


	public void testConstructor() {
		
		Date timestamp = new Date(1000L);
		
		JWKSetWithTimestamp jwkSetWithTimestamp = new JWKSetWithTimestamp(SAMPLE_JWK_SET, timestamp);
		assertEquals(SAMPLE_JWK_SET, jwkSetWithTimestamp.getJWKSet());
		assertEquals(timestamp, jwkSetWithTimestamp.getDate());
	}


	public void testMinimalConstructor() {
		
		JWKSetWithTimestamp jwkSetWithTimestamp = new JWKSetWithTimestamp(SAMPLE_JWK_SET);
		assertEquals(SAMPLE_JWK_SET, jwkSetWithTimestamp.getJWKSet());
		
		Date timestamp = jwkSetWithTimestamp.getDate();
		
		assertTrue(DateUtils.isWithin(timestamp, new Date(), 2));
	}
}
