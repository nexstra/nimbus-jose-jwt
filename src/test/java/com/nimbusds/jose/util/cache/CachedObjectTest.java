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

package com.nimbusds.jose.util.cache;


import static org.junit.Assert.*;

import org.junit.Test;


public class CachedObjectTest {


	@Test
	public void rejectNullObject() {
		
		try {
			new CachedObject<>(null, 1L, 2L);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The object must not be null", e.getMessage());
		}
	}
	
	
	@Test
	public void cachedString() {
		
		String s = "abc";
		CachedObject<String> cachedObject = new CachedObject<>(s, 1000L, 2000L);
		
		assertEquals(s, cachedObject.get());
		assertEquals(1000L, cachedObject.getTimestamp());
		assertEquals(2000L, cachedObject.getExpirationTime());
		
		assertTrue(cachedObject.isValid(1999L));
		assertFalse(cachedObject.isValid(2000L));
		assertFalse(cachedObject.isValid(2001L));
		
		assertFalse(cachedObject.isExpired(1999L));
		assertTrue(cachedObject.isExpired(2000L));
		assertTrue(cachedObject.isExpired(2001L));
	}
	
	
	@Test
	public void testComputeExpiration() {
		
		assertEquals(1500L, CachedObject.computeExpirationTime(1000L, 500L));
	}
}
