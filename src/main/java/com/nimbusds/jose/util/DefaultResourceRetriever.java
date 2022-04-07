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


import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import net.jcip.annotations.ThreadSafe;


/**
 * The default retriever of resources specified by HTTP(S) or file based URL.
 * Provides setting of a HTTP proxy, HTTP connect and read timeouts as well as
 * a size limit of the retrieved entity. Caching header directives are not
 * honoured.
 *
 * @author Vladimir Dzhuvinov
 * @author Artun Subasi
 * @author Imre Paladji
 * @version 2022-04-07
 */
@ThreadSafe
public class DefaultResourceRetriever extends AbstractRestrictedResourceRetriever implements RestrictedResourceRetriever {
	
	
	/**
	 * If {@code true} the disconnect method of the underlying
	 * HttpURLConnection is called after a successful or failed retrieval.
	 */
	private boolean disconnectAfterUse;
	
	
	/**
	 * For establishing the TLS connections, {@code null} to use the
	 * default one.
	 */
	private final SSLSocketFactory sslSocketFactory;


	/**
	 * The proxy to use when opening the HttpURLConnection. Can be
	 * {@code null}.
	 */
	private Proxy proxy;


	/**
	 * Creates a new resource retriever. The HTTP timeouts and entity size
	 * limit are set to zero (infinite).
	 */
	public DefaultResourceRetriever() {

		this(0, 0);
	}


	/**
	 * Creates a new resource retriever. The HTTP entity size limit is set
	 * to zero (infinite).
	 *
	 * @param connectTimeout The HTTP connects timeout, in milliseconds,
	 *                       zero for infinite. Must not be negative.
	 * @param readTimeout    The HTTP read timeout, in milliseconds, zero
	 *                       for infinite. Must not be negative.
	 */
	public DefaultResourceRetriever(final int connectTimeout, final int readTimeout) {

		this(connectTimeout, readTimeout, 0);
	}


	/**
	 * Creates a new resource retriever.
	 *
	 * @param connectTimeout The HTTP connects timeout, in milliseconds,
	 *                       zero for infinite. Must not be negative.
	 * @param readTimeout    The HTTP read timeout, in milliseconds, zero
	 *                       for infinite. Must not be negative.
	 * @param sizeLimit      The HTTP entity size limit, in bytes, zero for
	 *                       infinite. Must not be negative.
	 */
	public DefaultResourceRetriever(final int connectTimeout, final int readTimeout, final int sizeLimit) {

		this(connectTimeout, readTimeout, sizeLimit, true);
	}


	/**
	 * Creates a new resource retriever.
	 *
	 * @param connectTimeout     The HTTP connects timeout, in
	 *                           milliseconds, zero for infinite. Must not
	 *                           be negative.
	 * @param readTimeout        The HTTP read timeout, in milliseconds,
	 *                           zero for infinite. Must not be negative.
	 * @param sizeLimit          The HTTP entity size limit, in bytes, zero
	 *                           for infinite. Must not be negative.
	 * @param disconnectAfterUse If {@code true} the disconnect method of
	 *                           the underlying {@link HttpURLConnection}
	 *                           will be called after trying to retrieve
	 *                           the resource. Whether the TCP socket is
	 *                           actually closed or reused depends on the
	 *                           underlying HTTP implementation and the
	 *                           setting of the {@code keep.alive} system
	 *                           property.
	 */
	public DefaultResourceRetriever(final int connectTimeout,
					final int readTimeout,
					final int sizeLimit,
					final boolean disconnectAfterUse) {
		
		this(connectTimeout, readTimeout, sizeLimit, disconnectAfterUse, null);
	}
	
	
	/**
	 * Creates a new resource retriever.
	 *
	 * @param connectTimeout     The HTTP connects timeout, in
	 *                           milliseconds, zero for infinite. Must not
	 *                           be negative.
	 * @param readTimeout        The HTTP read timeout, in milliseconds,
	 *                           zero for infinite. Must not be negative.
	 * @param sizeLimit          The HTTP entity size limit, in bytes, zero
	 *                           for infinite. Must not be negative.
	 * @param disconnectAfterUse If {@code true} the disconnect method of
	 *                           the underlying {@link HttpURLConnection}
	 *                           will be called after trying to retrieve
	 *                           the resource. Whether the TCP socket is
	 *                           actually closed or reused depends on the
	 *                           underlying HTTP implementation and the
	 *                           setting of the {@code keep.alive} system
	 *                           property.
	 * @param sslSocketFactory   An SSLSocketFactory for establishing the
	 *                           TLS connections, {@code null} to use the
	 *                           default one.
	 */
	public DefaultResourceRetriever(final int connectTimeout,
					final int readTimeout,
					final int sizeLimit,
					final boolean disconnectAfterUse,
					final SSLSocketFactory sslSocketFactory) {
		super(connectTimeout, readTimeout, sizeLimit);
		this.disconnectAfterUse = disconnectAfterUse;
		this.sslSocketFactory = sslSocketFactory;
	}
	
	
	/**
	 * Returns {@code true} if the disconnect method of the underlying
	 * {@link HttpURLConnection} will be called after trying to retrieve
	 * the resource. Whether the TCP socket is actually closed or reused
	 * depends on the underlying HTTP implementation and the setting of the
	 * {@code keep.alive} system property.
	 *
	 * @return If {@code true} the disconnect method of the underlying
	 *         {@link HttpURLConnection} will be called after trying to
	 *         retrieve the resource.
	 */
	public boolean disconnectsAfterUse() {

		return disconnectAfterUse;
	}


	/**
	 * Controls calling of the disconnect method the underlying
	 * {@link HttpURLConnection} after trying to retrieve the resource.
	 * Whether the TCP socket is actually closed or reused depends on the
	 * underlying HTTP implementation and the setting of the
	 * {@code keep.alive} system property.
	 *
	 * If {@code true} the disconnect method of the underlying
	 * {@link HttpURLConnection} will be called after trying to
	 * retrieve the resource.
	 */
	public void setDisconnectsAfterUse(final boolean disconnectAfterUse) {

		this.disconnectAfterUse = disconnectAfterUse;
	}

	/**
	 * Returns the HTTP proxy to use when opening the HttpURLConnection to
	 * retrieve the resource. Note that the JVM may have a system wide
	 * proxy configured via the {@code https.proxyHost} Java system
	 * property.
	 *
	 * @return The proxy to use or {@code null} if no proxy should be used.
	 */
	public Proxy getProxy() {

		return proxy;
	}

	/**
	 * Sets the HTTP proxy to use when opening the HttpURLConnection to
	 * retrieve the resource. Note that the JVM may have a system wide
	 * proxy configured via the {@code https.proxyHost} Java system
	 * property.
	 *
	 * @param proxy The proxy to use or {@code null} if no proxy should be
	 *              used.
	 */
	public void setProxy(final Proxy proxy) {

		this.proxy = proxy;
	}


	@Override
	public Resource retrieveResource(final URL url)
		throws IOException {

		URLConnection con = null;
		try {
			if ("file".equals(url.getProtocol())) {
				con = openFileConnection(url);
			} else {
				// TODO Switch to openHTTPConnected when the
				// deprecated openConnection method is removed
				con = openConnection(url);
			}

			con.setConnectTimeout(getConnectTimeout());
			con.setReadTimeout(getReadTimeout());
			
			if (con instanceof HttpsURLConnection && sslSocketFactory != null) {
				((HttpsURLConnection)con).setSSLSocketFactory(sslSocketFactory);
			}
			
			if (con instanceof HttpURLConnection && getHeaders() != null && !getHeaders().isEmpty()) {
				for (Map.Entry<String, List<String>> entry : getHeaders().entrySet()) {
					for (String value: entry.getValue()) {
						con.addRequestProperty(entry.getKey(), value);
					}
				}
			}

			final String content;
			try (InputStream inputStream = getInputStream(con, getSizeLimit())) {
				content = IOUtils.readInputStreamToString(inputStream, StandardCharset.UTF_8);
			}

			if (con instanceof HttpURLConnection) {
				// Check HTTP code + message
				HttpURLConnection httpCon = (HttpURLConnection) con;
				final int statusCode = httpCon.getResponseCode();
				final String statusMessage = httpCon.getResponseMessage();
				
				// Ensure 2xx status code
				if (statusCode > 299 || statusCode < 200) {
					throw new IOException("HTTP " + statusCode + ": " + statusMessage);
				}
			}
			
			String contentType = con instanceof HttpURLConnection ? con.getContentType() : null;
			
			return new Resource(content, contentType);

		} catch (Exception e) {
			
			if (e instanceof IOException) {
				throw e;
			}
			
			throw new IOException("Couldn't open URL connection: " + e.getMessage(), e);
			
		} finally {
			if (disconnectAfterUse && con instanceof HttpURLConnection) {
				((HttpURLConnection) con).disconnect();
			}
		}
	}
	

	/**
	 * Opens a connection the specified HTTP(S) URL. Uses the configured
	 * {@link Proxy} if available.
	 *
	 * @see #openHTTPConnection
	 *
	 * @param url The URL of the resource. Its scheme must be HTTP or
	 *            HTTPS. Must not be {@code null}.
	 *
	 * @return The opened HTTP(S) connection
	 *
	 * @throws IOException If the HTTP(S) connection to the specified URL
	 *                     failed.
	 */
	@Deprecated
	protected HttpURLConnection openConnection(final URL url) throws IOException {
		return openHTTPConnection(url);
	}
	

	/**
	 * Opens a connection the specified HTTP(S) URL. Uses the configured
	 * {@link Proxy} if available.
	 *
	 * @param url The URL of the resource. Its scheme must be "http" or
	 *            "https". Must not be {@code null}.
	 *
	 * @return The opened HTTP(S) connection
	 *
	 * @throws IOException If the HTTP(S) connection to the specified URL
	 *                     failed.
	 */
	protected HttpURLConnection openHTTPConnection(final URL url) throws IOException {
		if (proxy != null) {
			return (HttpURLConnection)url.openConnection(proxy);
		} else {
			return (HttpURLConnection)url.openConnection();
		}
	}
	
	
	/**
	 * Opens a connection the specified file URL.
	 *
	 * @param url The URL of the resource. Its scheme must be "file". Must
	 *            not be {@code null}.
	 *
	 * @return The opened file connection.
	 *
	 * @throws IOException If the file connection to the specified URL
	 *                     failed.
	 */
	protected URLConnection openFileConnection(final URL url) throws IOException {
		
		return url.openConnection();
	}


	private InputStream getInputStream(final URLConnection con, final int sizeLimit)
		throws IOException {

		InputStream inputStream = con.getInputStream();

		return sizeLimit > 0 ? new BoundedInputStream(inputStream, getSizeLimit()) : inputStream;
	}
}
