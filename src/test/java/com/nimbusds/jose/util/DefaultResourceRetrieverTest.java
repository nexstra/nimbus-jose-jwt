/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
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

package com.nimbusds.jose.util;


import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static net.jadler.Jadler.*;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class DefaultResourceRetrieverTest {
	

	@Test
	public void testDefaultSettings() {

		DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever();
		assertEquals(0, resourceRetriever.getConnectTimeout());
		assertEquals(0, resourceRetriever.getReadTimeout());
		assertEquals(0, resourceRetriever.getSizeLimit());
		assertTrue(resourceRetriever.disconnectsAfterUse());
		assertNull(resourceRetriever.getProxy());
	}


	@Test
	public void testSetters() {

		DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever();
		assertEquals(0, resourceRetriever.getConnectTimeout());
		assertEquals(0, resourceRetriever.getReadTimeout());
		assertEquals(0, resourceRetriever.getSizeLimit());

		resourceRetriever.setConnectTimeout(100);
		assertEquals(100, resourceRetriever.getConnectTimeout());

		resourceRetriever.setReadTimeout(200);
		assertEquals(200, resourceRetriever.getReadTimeout());

		resourceRetriever.setSizeLimit(300);
		assertEquals(300, resourceRetriever.getSizeLimit());
		
		resourceRetriever.setDisconnectsAfterUse(false);
		assertFalse(resourceRetriever.disconnectsAfterUse());

		resourceRetriever.setProxy(Proxy.NO_PROXY);
		assertEquals(Proxy.NO_PROXY, resourceRetriever.getProxy());
	}


	@Test
	public void testTimeoutConstructor() {

		DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(100, 200);
		assertEquals(100, resourceRetriever.getConnectTimeout());
		assertEquals(200, resourceRetriever.getReadTimeout());
		assertEquals(0, resourceRetriever.getSizeLimit());
		assertTrue(resourceRetriever.disconnectsAfterUse());
	}


	@Test
	public void testTimeoutConstructorAndSizeLimitConstructor() {

		DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(100, 200, 300);
		assertEquals(100, resourceRetriever.getConnectTimeout());
		assertEquals(200, resourceRetriever.getReadTimeout());
		assertEquals(300, resourceRetriever.getSizeLimit());
		assertTrue(resourceRetriever.disconnectsAfterUse());
	}


	@Test
	public void testFullConstructor() {

		DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(100, 200, 300, false);
		assertEquals(100, resourceRetriever.getConnectTimeout());
		assertEquals(200, resourceRetriever.getReadTimeout());
		assertEquals(300, resourceRetriever.getSizeLimit());
		assertFalse(resourceRetriever.disconnectsAfterUse());
	}


	@Before
	public void setUp() {
		initJadler();
	}


	@After
	public void tearDown() {
		closeJadler();
	}


	@Test
	public void testRetrieveOK()
		throws Exception {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("A", "B");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/c2id/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(JSONObjectUtils.toJSONString(jsonObject));

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever();
		Resource resource = resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));
		assertEquals("application/json", resource.getContentType());
		jsonObject = JSONObjectUtils.parse(resource.getContent());
		assertEquals("B", jsonObject.get("A"));
	}


	@Test
	public void testRetrieveOK_noDisconnectAfterUse()
		throws Exception {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("A", "B");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/c2id/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(JSONObjectUtils.toJSONString(jsonObject));

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(0, 0, 0, false);
		Resource resource = resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));
		assertEquals("application/json", resource.getContentType());
		jsonObject = JSONObjectUtils.parse(resource.getContent());
		assertEquals("B", jsonObject.get("A"));
	}


	@Test
	public void testRetrieveOK_noDisconnectAfterUse_loop()
		throws Exception {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("A", "B");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/c2id/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(JSONObjectUtils.toJSONString(jsonObject));

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(0, 0, 0, false);
		
		for (int i=0; i<100; i++) {
			Resource resource = resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));
			assertEquals("application/json", resource.getContentType());
			jsonObject = JSONObjectUtils.parse(resource.getContent());
			assertEquals("B", jsonObject.get("A"));
		}
	}


	@Test
	public void testRetrieveOKWithoutContentType()
		throws Exception {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("A", "B");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/c2id/jwks.json")
			.respond()
			.withStatus(200)
			.withBody(JSONObjectUtils.toJSONString(jsonObject));

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever();
		Resource resource = resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));
		assertNull(resource.getContentType());
		jsonObject = JSONObjectUtils.parse(resource.getContent());
		assertEquals("B", jsonObject.get("A"));
	}


	@Test
	public void testIgnoreInvalidContentType()
		throws Exception {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("A", "B");

		String invalidContentType = "moo/boo/foo";

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/c2id/jwks.json")
			.respond()
			.withStatus(200)
			.withContentType(invalidContentType)
			.withBody(JSONObjectUtils.toJSONString(jsonObject));

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever();

		Resource resource = resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));
		assertEquals(invalidContentType, resource.getContentType());
	}


	@Test
	public void testRetrieve2xxWithProxy()
		throws Exception {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("A", "B");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/c2id/jwks.json")
			.respond()
			.withStatus(201)
			.withHeader("Content-Type", "application/json")
			.withBody(JSONObjectUtils.toJSONString(jsonObject));

		DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever();
		resourceRetriever.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", port())));
		Resource resource = resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));
		assertEquals("application/json", resource.getContentType());
		jsonObject = JSONObjectUtils.parse(resource.getContent());
		assertEquals("B", jsonObject.get("A"));
	}


	@Test
	public void testRetrieve2xx()
			throws Exception {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("A", "B");

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/c2id/jwks.json")
				.respond()
				.withStatus(201)
				.withHeader("Content-Type", "application/json")
				.withBody(JSONObjectUtils.toJSONString(jsonObject));

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever();
		Resource resource = resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));
		assertEquals("application/json", resource.getContentType());
		jsonObject = JSONObjectUtils.parse(resource.getContent());
		assertEquals("B", jsonObject.get("A"));
	}


	@Test
	public void testConnectTimeout()
			throws Exception {

		ServerSocket serverSocket = new ServerSocket(0);
		int port = serverSocket.getLocalPort();
		serverSocket.close();

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(50, 0);

		URL url = new URL("http://localhost:" + port + "/c2id/jwks.json");
		
		try {
			resourceRetriever.retrieveResource(url);
			fail();
		} catch (IOException e) {
			assertTrue(e.getMessage().startsWith("Connection refused"));
		}
	}


	@Test
	public void testConnectTimeoutWithProxy()
			throws Exception {

		ServerSocket serverSocket = new ServerSocket(0);
		int proxyPort = serverSocket.getLocalPort();
		serverSocket.close();

		DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(50, 0);
		resourceRetriever.setProxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", proxyPort)));

		URL url = new URL("http://localhost:" + port() + "/c2id/jwks.json");
		
		try {
			resourceRetriever.retrieveResource(url);
			fail();
		} catch (IOException e) {
			assertTrue(e.getMessage().startsWith("Connection refused"));
		}
	}


	@Test
	public void testReadTimeout()
		throws Exception {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("A", "B");

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/c2id/jwks.json")
				.respond()
				.withDelay(100L, TimeUnit.MILLISECONDS)
				.withStatus(200)
				.withHeader("Content-Type", "application/json")
				.withBody(JSONObjectUtils.toJSONString(jsonObject));

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(0, 50);

		URL url = new URL("http://localhost:" + port() + "/c2id/jwks.json");
		
		try {
			resourceRetriever.retrieveResource(url);
			fail();
		} catch (IOException e) {
			assertEquals("Read timed out", e.getMessage());
		}
	}


	@Test
	public void testSizeLimit()
		throws Exception {

		int size = 100000;
		StringBuilder sb = new StringBuilder();
		for (int i=0; i < size; i++) {
			sb.append('a');
		}

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/c2id/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "text/plain")
			.withBody(sb.toString());

		int sizeLimit = 50000;
		assertTrue(sizeLimit < size);
		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever(0, 0, sizeLimit);

		URL url = new URL("http://localhost:" + port() + "/c2id/jwks.json");

		try {
			resourceRetriever.retrieveResource(url);
			fail();
		} catch (IOException e) {
			// Size overrun exception poses as file not found
			assertEquals("Exceeded configured input limit of 50000 bytes", e.getMessage());
		}
	}

	@Test
	public void testHeaders()
		throws Exception {

		List<String> userAgentHeaderValue = Arrays.asList("NewAgent");
		List<String> multipleValueHeader = Arrays.asList("Value1", "Value2");

		Map<String,Object> jsonObject = new HashMap<>();
		jsonObject.put("A", "B");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/c2id/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(JSONObjectUtils.toJSONString(jsonObject));

		RestrictedResourceRetriever resourceRetriever = new DefaultResourceRetriever();
		Map<String, List<String>> headers = new HashMap<>();
		headers.put("User-Agent", userAgentHeaderValue);
		headers.put("MultipleValues", multipleValueHeader);
		resourceRetriever.setHeaders(headers);

		Resource resource = resourceRetriever.retrieveResource(new URL("http://localhost:" + port() + "/c2id/jwks.json"));

		verifyThatRequest()
			.havingHeader("User-Agent", equalTo(userAgentHeaderValue))
			.havingHeader("MultipleValues", equalTo(multipleValueHeader))
			.receivedOnce();
	}
	
	
	@Test
	public void testFileResource() throws IOException {
		
		File file = File.createTempFile("temp", null);
		
		final String content = "Hello, world!";
		
		Files.write(file.toPath(), content.getBytes(StandardCharsets.UTF_8));
		
		URL url = new URL("file:///" + file.getAbsolutePath());
		
		Resource resource = new DefaultResourceRetriever().retrieveResource(url);
		
		assertEquals(content, resource.getContent());
		assertNull(resource.getContentType());
		
		file.deleteOnExit();
	}
	
	
	@Test
	public void testFileResourceNotFound() throws IOException {
		
		String filePath = "/" + UUID.randomUUID();
		
		URL url = new URL("file://" + filePath);
		
		try {
			new DefaultResourceRetriever().retrieveResource(url);
			fail();
		} catch (IOException e) {
			assertEquals(filePath + " (No such file or directory)", e.getMessage());
		}
	}
}
