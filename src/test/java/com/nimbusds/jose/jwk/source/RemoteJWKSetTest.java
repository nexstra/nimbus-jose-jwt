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

package com.nimbusds.jose.jwk.source;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jose.util.StandardCharset;
import net.jadler.Request;
import net.jadler.stubbing.Responder;
import net.jadler.stubbing.StubResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static net.jadler.Jadler.closeJadler;
import static net.jadler.Jadler.initJadler;
import static net.jadler.Jadler.onRequest;
import static net.jadler.Jadler.port;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


public class RemoteJWKSetTest {

	private static final RSAKey RSA_JWK_1;
	private static final RSAKey RSA_JWK_2;
	private static final RSAKey RSA_JWK_3;
	static {
		try {
			RSA_JWK_1 = new RSAKeyGenerator(2048)
				.keyID("1")
				.generate();
			RSA_JWK_2 = new RSAKeyGenerator(2048)
				.keyID("2")
				.generate();
			RSA_JWK_3 = new RSAKeyGenerator(2048)
				.keyID("3")
				.generate();
			
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}

	@Before
	public void setUp() {
		initJadler();
	}

	@After
	public void tearDown() {
		closeJadler();
		
		System.clearProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpConnectTimeout");
		System.clearProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpReadTimeout");
		System.clearProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpSizeLimit");
	}

	@Test
	public void testConstants() {
		assertEquals(500, JWKSourceBuilder.DEFAULT_HTTP_CONNECT_TIMEOUT);
		assertEquals(500, JWKSourceBuilder.DEFAULT_HTTP_READ_TIMEOUT);
		assertEquals(50 * 1024, JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT);
	}

	@Test
	public void testSimplifiedConstructor()
		throws Exception {

		JWKSet jwkSet = new JWKSet(Arrays.asList(RSA_JWK_1, (JWK)RSA_JWK_2));

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/jwks.json")
				.respond()
				.withStatus(200)
				.withHeader("Content-Type", "application/json")
				.withBody(JSONObjectUtils.toJSONString(jwkSet.toJSONObject(true)));

		RemoteJWKSet<?> jwkSetSource = (RemoteJWKSet<?>) JWKSourceBuilder.newBuilder(jwkSetURL).build();

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(RSA_JWK_1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(RSA_JWK_1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());

		JWKSetProvider provider = jwkSetSource.getProvider();
		JWKSet out = provider.getJWKSet(false);
		assertTrue(out.getKeys().get(0) instanceof RSAKey);
		assertTrue(out.getKeys().get(1) instanceof RSAKey);
		assertEquals("1", out.getKeys().get(0).getKeyID());
		assertEquals("2", out.getKeys().get(1).getKeyID());
		assertEquals(2, out.getKeys().size());
	}

	@Test
	public void testWithExplicitRetriever()
		throws Exception {

		JWKSet jwkSet = new JWKSet(Arrays.asList(RSA_JWK_1, (JWK)RSA_JWK_2));

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody( JSONObjectUtils.toJSONString(jwkSet.toJSONObject(true)));

		RemoteJWKSet<?> jwkSetSource = (RemoteJWKSet<?>) JWKSourceBuilder.newBuilder(jwkSetURL).build();

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(RSA_JWK_1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(RSA_JWK_1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());

		JWKSetProvider provider = jwkSetSource.getProvider();
		JWKSet out = provider.getJWKSet(false);
		assertTrue(out.getKeys().get(0) instanceof RSAKey);
		assertTrue(out.getKeys().get(1) instanceof RSAKey);
		assertEquals("1", out.getKeys().get(0).getKeyID());
		assertEquals("2", out.getKeys().get(1).getKeyID());
		assertEquals(2, out.getKeys().size());
	}

	@Test
	public void testSelectRSAByKeyID_defaultRetriever()
		throws Exception {

		JWKSet jwkSet = new JWKSet(Arrays.asList(RSA_JWK_1, (JWK)RSA_JWK_2));

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(JSONObjectUtils.toJSONString(jwkSet.toJSONObject(true)));

		JWKSource<?> jwkSetSource = JWKSourceBuilder.newBuilder(jwkSetURL).build();

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(RSA_JWK_1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(RSA_JWK_1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());
	}

	@Test
	public void testRefreshRSAByKeyID_defaultRetriever()
		throws Exception {

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respondUsing(new Responder() {
				private int count = 0;
				@Override
				public StubResponse nextResponse(Request request) {

					if (! request.getMethod().equalsIgnoreCase("GET")) {
						return StubResponse.builder().status(405).build();
					}

					if (count == 0) {
						++count;
						return StubResponse.builder()
							.status(200)
							.header("Content-Type", "application/json")
							.body( JSONObjectUtils.toJSONString(new JWKSet(Arrays.asList((JWK)RSA_JWK_1, (JWK)RSA_JWK_2)).toJSONObject()), StandardCharset.UTF_8)
							.build();
					}

					// Add 3rd key
					return StubResponse.builder()
						.status(200)
						.header("Content-Type", "application/json")
						.body( JSONObjectUtils.toJSONString(new JWKSet(Arrays.asList(RSA_JWK_1, RSA_JWK_2, (JWK)RSA_JWK_3)).toJSONObject()), StandardCharset.UTF_8)
						.build();
				}
			});

		RemoteJWKSet<?> jwkSetSource = (RemoteJWKSet<?>) JWKSourceBuilder.newBuilder(jwkSetURL).rateLimited(0L).build();

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(RSA_JWK_1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(RSA_JWK_1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());

		// Check cache
		JWKSet out = jwkSetSource.getProvider().getJWKSet(false);
		assertTrue(out.getKeys().get(0) instanceof RSAKey);
		assertTrue(out.getKeys().get(1) instanceof RSAKey);
		assertEquals("1", out.getKeys().get(0).getKeyID());
		assertEquals("2", out.getKeys().get(1).getKeyID());
		assertEquals(2, out.getKeys().size());

		// Select 3rd key, expect refresh of JWK set
		matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("3").build()), null);

		m1 = (RSAKey) matches.get(0);
		assertEquals(RSA_JWK_3.getPublicExponent(), m1.getPublicExponent());
		assertEquals(RSA_JWK_3.getModulus(), m1.getModulus());
		assertEquals("3", m1.getKeyID());

		assertEquals(1, matches.size());
	}

	@Test
	public void testWithFailoverJWKSource_immutableJWKSet()
		throws Exception {

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/jwks.json")
				.respond()
				.withStatus(404);

		JWKSource failover = new ImmutableJWKSet<>(new JWKSet(Arrays.asList((JWK) RSA_JWK_1, (JWK) RSA_JWK_2)));

		JWKSource<?> jwkSetSource = JWKSourceBuilder.newBuilder(jwkSetURL).failover(failover).build();

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(RSA_JWK_1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(RSA_JWK_1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());

		// TODO 
		// assertNull("Cache must not be updated with failover JWK set", jwkSetSource.getCachedJWKSet());
	}

	@Test
	public void testWithFailoverJWKSource_remoteJWKSet()
		throws Exception {

		JWKSet jwkSet = new JWKSet(Arrays.asList(RSA_JWK_1, (JWK) RSA_JWK_2));

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");
		URL failoverJWKSetURL = new URL("http://localhost:" + port() + "/failover-jwks.json");

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/jwks.json")
				.respond()
				.withStatus(404);

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/failover-jwks.json")
				.respond()
				.withStatus(200)
				.withHeader("Content-Type", "application/json")
				.withBody(JSONObjectUtils.toJSONString(jwkSet.toJSONObject(true)));

		JWKSource failover = JWKSourceBuilder.newBuilder(failoverJWKSetURL).build();

		JWKSource<?> jwkSetSource = JWKSourceBuilder.newBuilder(jwkSetURL).failover(failover).build();

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(RSA_JWK_1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(RSA_JWK_1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());

		// 
		// assertNull("Cache must not be updated with failover JWK set", jwkSetSource.getCachedJWKSet());
	}

	@Test
	public void testWithFailoverJWKSource_fail()
		throws Exception {

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");
		URL failoverJWKSetURL = new URL("http://localhost:" + port() + "/failover-jwks.json");

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/jwks.json")
				.respond()
				.withStatus(404);

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/failover-jwks.json")
				.respond()
				.withStatus(404);

		JWKSource failover = JWKSourceBuilder.newBuilder(failoverJWKSetURL).build();

		JWKSource<?> jwkSetSource = JWKSourceBuilder.newBuilder(jwkSetURL).failover(failover).build();

		try {
			jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);
			fail();
		} catch (KeySourceException e) {
			assertEquals(
					"Couldn't retrieve remote JWK set: " + jwkSetURL +
							"; Failover JWK source retrieval failed with: " +
							"Couldn't retrieve remote JWK set: " + failoverJWKSetURL,
					e.getMessage()
			);
			Throwable cause = e.getCause();
			assertTrue(cause instanceof KeySourceException);
			assertEquals("Couldn't retrieve remote JWK set: " + failoverJWKSetURL, cause.getMessage());
		}
	}

	@Test
	public void testInvalidJWKSetURL()
		throws Exception {

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/jwks.json")
				.respond()
				.withStatus(404);

		RemoteJWKSet<?> jwkSetSource = (RemoteJWKSet<?>) JWKSourceBuilder.newBuilder(jwkSetURL).build();

		try {
			jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);
		} catch (RemoteKeySourceException e) {
			assertEquals("Couldn't retrieve remote JWK set: " + jwkSetURL, e.getMessage());
			assertTrue(e.getCause() instanceof FileNotFoundException);
			assertEquals(jwkSetURL.toString(), e.getCause().getMessage());
		}
	}

	@Test
	public void testTimeout()
		throws Exception {

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest().respond().withDelay(800, TimeUnit.MILLISECONDS);

		RemoteJWKSet<?> jwkSetSource = (RemoteJWKSet<?>) JWKSourceBuilder.newBuilder(jwkSetURL).build();

		try {
			jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
			fail();
		} catch (RemoteKeySourceException e) {
			assertEquals("Couldn't retrieve remote JWK set: Read timed out", e.getMessage());
			assertTrue(e.getCause() instanceof SocketTimeoutException);
			assertEquals("Read timed out", e.getCause().getMessage());
		}
	}

	@Test
	public void testTimeout_withFailover()
		throws Exception {

		JWKSet jwkSet = new JWKSet(Arrays.asList(RSA_JWK_1, (JWK) RSA_JWK_2));

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");
		URL failoverJWKSetURL = new URL("http://localhost:" + port() + "/failover-jwks.json");

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/jwks.json")
				.respond()
				.withDelay(800, TimeUnit.MILLISECONDS);

		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/failover-jwks.json")
				.respond()
				.withStatus(200)
				.withHeader("Content-Type", "application/json")
				.withBody(JSONObjectUtils.toJSONString(jwkSet.toJSONObject(true)));

		JWKSource failover = new ImmutableJWKSet<>(new JWKSet(Arrays.asList((JWK) RSA_JWK_1, RSA_JWK_2)));
		FailoverJWKSource<?> jwkSetSource = (FailoverJWKSource<?>) JWKSourceBuilder.newBuilder(jwkSetURL).failover(failover).build();

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(RSA_JWK_1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(RSA_JWK_1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());

		// TODO
		// assertNull("Cache must not be updated with failover JWK set", jwkSetSource.getCachedJWKSet());
	}

	@Test
	public void testResolveDefaults() {

		assertEquals(JWKSourceBuilder.DEFAULT_HTTP_CONNECT_TIMEOUT, JWKSourceBuilder.resolveDefaultHTTPConnectTimeout());
		assertEquals(JWKSourceBuilder.DEFAULT_HTTP_READ_TIMEOUT, JWKSourceBuilder.resolveDefaultHTTPReadTimeout());
		assertEquals(JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT, JWKSourceBuilder.resolveDefaultHTTPSizeLimit());
	}

	@Test
	public void testResolveDefaults_systemPropertyOverride() {

		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpConnectTimeout", "250");
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpReadTimeout", "100");
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpSizeLimit", "10000");

		assertEquals(250, JWKSourceBuilder.resolveDefaultHTTPConnectTimeout());
		assertEquals(100, JWKSourceBuilder.resolveDefaultHTTPReadTimeout());
		assertEquals(10_000, JWKSourceBuilder.resolveDefaultHTTPSizeLimit());
	}

	@Test
	public void testDefaultsSetBySystemProperties_readTimeout()
		throws Exception {

		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpConnectTimeout", "250");
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpReadTimeout", "100");
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpSizeLimit", "10000");

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest().respond().withDelay(350, TimeUnit.MILLISECONDS);

		RemoteJWKSet<?> jwkSetSource = (RemoteJWKSet<?>) JWKSourceBuilder.newBuilder(jwkSetURL).build();

		BaseJWKSetProvider provider = (BaseJWKSetProvider) jwkSetSource.getProvider();
		while (provider.getProvider() instanceof BaseJWKSetProvider) {
			provider = (BaseJWKSetProvider) provider.getProvider();
		}
		ResourceRetrieverJWKSetProvider p = (ResourceRetrieverJWKSetProvider) provider.getProvider();
		DefaultResourceRetriever resourceRetriever = (DefaultResourceRetriever) p.getResourceRetriever();

		assertEquals(250, resourceRetriever.getConnectTimeout());
		assertEquals(100, resourceRetriever.getReadTimeout());
		assertEquals(10_000, resourceRetriever.getSizeLimit());

		try {
			jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
			fail();
		} catch (RemoteKeySourceException e) {
			assertEquals("Couldn't retrieve remote JWK set: Read timed out", e.getMessage());
			assertTrue(e.getCause() instanceof SocketTimeoutException);
			assertEquals("Read timed out", e.getCause().getMessage());
		}
	}

	@Test
	public void testDefaultsSetBySystemProperties_ignoreNumberFormatExceptions()
		throws Exception {

		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpConnectTimeout", "aaa");
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpReadTimeout", "bbb");
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpSizeLimit", "ccc");

		URL jwkSetURL = new URL("https://example.com/jwks.json");

		RemoteJWKSet<?> jwkSetSource = (RemoteJWKSet<?>) JWKSourceBuilder.newBuilder(jwkSetURL).build();

		BaseJWKSetProvider provider = (BaseJWKSetProvider) jwkSetSource.getProvider();
		while (provider.getProvider() instanceof BaseJWKSetProvider) {
			provider = (BaseJWKSetProvider) provider.getProvider();
		}
		ResourceRetrieverJWKSetProvider p = (ResourceRetrieverJWKSetProvider) provider.getProvider();
		DefaultResourceRetriever resourceRetriever = (DefaultResourceRetriever) p.getResourceRetriever();

		assertEquals(JWKSourceBuilder.DEFAULT_HTTP_CONNECT_TIMEOUT, resourceRetriever.getConnectTimeout());
		assertEquals(JWKSourceBuilder.DEFAULT_HTTP_READ_TIMEOUT, resourceRetriever.getReadTimeout());
		assertEquals(JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT, resourceRetriever.getSizeLimit());
	}
	
	@Test
	public void testCacheUpdateIsOnlyExecutedOnce()
		throws Exception {
		
		final JWKSet jwkSet = new JWKSet(Collections.singletonList((JWK) RSA_JWK_1));
		
		int numberOfThreads = 10;
		final CountDownLatch latch = new CountDownLatch(numberOfThreads);
		
		final URL jwkSetURL = new URL("http://localhost/jwks.json");
		final AtomicInteger invocationCounter = new AtomicInteger(0);
		ResourceRetriever retriever = new ResourceRetriever() {
			@Override
			public Resource retrieveResource(URL url) {
				invocationCounter.incrementAndGet();
				final String content = JSONObjectUtils.toJSONString(jwkSet.toJSONObject(true));
				return new Resource(content, "application/json");
			}
		};
		final RemoteJWKSet<SecurityContext> jwkSetSource = (RemoteJWKSet<SecurityContext>) JWKSourceBuilder.newBuilder(jwkSetURL, retriever).build();
		
		ExecutorService executorService = Executors.newFixedThreadPool(numberOfThreads);
		List<Future<List<JWK>>> futures = new ArrayList<>();
		
		for (int i = 0; i < numberOfThreads; i++) {
			Future<List<JWK>> future = executorService.submit(new Callable<List<JWK>>() {
				@Override
				public List<JWK> call() {
					try {
						// the latch will be released when all threads have been started to increase likelihood of concurrency issues
						latch.countDown();
						latch.await(1, TimeUnit.MINUTES);
						return jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);

					} catch (KeySourceException e) {
						throw new RuntimeException(e);

					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
						throw new RuntimeException(e);
					}
				}
			});
			
			futures.add(future);
		}
		
		for (Future<List<JWK>> future : futures) {
			List<JWK> result = future.get(1, TimeUnit.MINUTES);
			assertEquals(1, result.size());
			assertEquals(RSA_JWK_1.getKeyID(), result.get(0).getKeyID());
		}
		
		executorService.shutdown();
		executorService.awaitTermination(1, TimeUnit.SECONDS);
		
		assertEquals("Retriever must be called exactly once", 1, invocationCounter.intValue());
	}
	
	@Test
	public void testCacheRefreshIfKeyIsNotFoundIsOnlyExecutedOnce()
		throws Exception {
		
		final RSAKey rsaJWKOld = new RSAKeyGenerator(2048)
			.keyID("oldKeyID")
			.generate();
		
		final RSAKey rsaJWKNew = new RSAKeyGenerator(2048)
			.keyID("newKeyID")
			.generate();
		
		final JWKSet jwkSetOld = new JWKSet(Collections.singletonList((JWK) rsaJWKOld));
		final JWKSet jwkSetNew = new JWKSet(Collections.singletonList((JWK) rsaJWKNew));
		
		int numberOfThreads = 20;
		final CountDownLatch latch = new CountDownLatch(numberOfThreads);
		
		final URL jwkSetURL = new URL("http://localhost/jwks.json");
		
		final AtomicInteger invocationCounter = new AtomicInteger(0);

		ResourceRetriever retriever = new ResourceRetriever() {

			@Override
			public Resource retrieveResource(URL url) throws IOException {
				invocationCounter.incrementAndGet();
				final String content = JSONObjectUtils.toJSONString(jwkSetNew.toJSONObject(true));
				return new Resource(content, "application/json");
			}

		};

		final RemoteJWKSet<SecurityContext> jwkSetSource = (RemoteJWKSet<SecurityContext>) JWKSourceBuilder.newBuilder(jwkSetURL, retriever).build();

		ExecutorService executorService = Executors.newFixedThreadPool(numberOfThreads);
		List<Future<List<JWK>>> futures = new ArrayList<>();

		for (int i = 0; i < numberOfThreads; i++) {

			Future<List<JWK>> future = executorService.submit(new Callable<List<JWK>>() {
				@Override
				public List<JWK> call() {
					try {
						// the latch will be released when all threads have been started to increase likelihood of concurrency issues
						latch.countDown();
						latch.await(1, TimeUnit.MINUTES);
						return jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID(rsaJWKNew.getKeyID()).build()), null);
					} catch (KeySourceException e) {
						throw new RuntimeException(e);

					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
						throw new RuntimeException(e);
					}
				}
			});
			
			futures.add(future);
		}

		for (Future<List<JWK>> future : futures) {
			List<JWK> result = future.get(1, TimeUnit.MINUTES);
			assertEquals( 1, result.size());
			assertEquals(rsaJWKNew.getKeyID(), result.get(0).getKeyID());
			
		}
		
		executorService.shutdown();
		executorService.awaitTermination(1, TimeUnit.SECONDS);
		
		assertEquals("Retriever must be called exactly once", 1, invocationCounter.intValue());
	}
}
