/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2022, Connect2id Ltd.
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

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;


/**
 * {@linkplain JWKSetSource} with with retry capability to work around
 * transient network issues. In cases when the underlying source throws a
 * {@linkplain JWKSetUnavailableException} the retrieval is tried once again.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-09
 */
@ThreadSafe
public class RetryingJWKSetSource<C extends SecurityContext> extends JWKSetSourceWrapper<C> {

	public interface Listener<C extends SecurityContext> extends JWKSetSourceListener<C> {
		void onRetrying(Exception e, C context);
	}
	
	private final Listener<C> listener;
	
	
	/**
	 * Creates a new JWK set source with support for retrial.
	 *
	 * @param source   The JWK set source to decorate. Must not be
	 *                 {@code null}.
	 * @param listener The listener, {@code null} if not specified.
	 */
	public RetryingJWKSetSource(final JWKSetSource<C> source, final Listener<C> listener) {
		super(source);
		this.listener = listener;
	}

	
	@Override
	public JWKSet getJWKSet(final boolean forceReload, final long currentTime, final C context)
		throws KeySourceException {
		
		try {
			return getSource().getJWKSet(forceReload, currentTime, context);
			
		} catch (JWKSetUnavailableException e) {
			// assume transient network issue, retry once
			if (listener != null) {
				listener.onRetrying(e, context);
			}
			return getSource().getJWKSet(forceReload, currentTime, context);
		}
	}
}
