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

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * Default 'lazy' implementation of health provider. <br>
 * <br>
 * Returns bad health if<br>
 * - a previous invocation has failed, and a new invocation (by the indicator, from the top level) fails as well. <br>
 * <br>
 * Returns good health if<br>
 * - a previous invocation was successful, or<br>
 * - a previous invocation has failed, but a new invocation (by the the indicator, from the top level) is successful.<br>
 * <br>
 * Calls to this health indicator does not trigger a (remote) refresh if the last call to the
 * underlying provider was successful. 
 */

public class DefaultHealthJWKSetProvider extends BaseJWKSetProvider {

	private static final Logger LOGGER = Logger.getLogger(DefaultHealthJWKSetProvider.class.getName());

	/** The state of the below provider */
	private volatile JWKSetHealth providerStatus;
	
	/** The state of the top level provider */
	private volatile JWKSetHealth status;

	/**
	 * Provider to invoke when refreshing state. This should be the top level
	 * provider, so that caches are actually populated and so on.
	 */
	private JWKSetProvider refreshProvider;

	public DefaultHealthJWKSetProvider(JWKSetProvider provider) {
		super(provider);
	}

	@Override
	public JWKSet getJWKSet(long time, boolean forceUpdate) throws KeySourceException {
		JWKSet list = null;
		try {
			list = provider.getJWKSet(time, forceUpdate);
		} finally {
			setProviderStatus(new JWKSetHealth(time, list != null));
		}

		return list;
	}

	protected void setProviderStatus(JWKSetHealth status) {
		this.providerStatus = status;
	}

	@Override
	public JWKSetHealth getHealth(boolean refresh) {
		return getHealth(System.currentTimeMillis(), refresh);
	}

	protected JWKSetHealth getHealth(long time, boolean refresh) {
		if(!refresh) {
			JWKSetHealth threadSafeStatus = this.status; // defensive copy
			if(threadSafeStatus != null) {
				return threadSafeStatus;
			}
			// not allowed to refresh
			// use the latest underlying provider status, if available
			return providerStatus;
		}

		// assuming a successful call to the underlying provider always results
		// in a healthy top-level provider. 
		//
		// If the last call to the underlying provider is not successful
		// get the JWKs from the top level provider (without forcing a refresh)
		// so that the cache is refreshed if necessary, so an unhealthy status
		// can turn to a healthy status just by checking the health
		JWKSetHealth threadSafeStatus = this.providerStatus; // defensive copy
		if (threadSafeStatus == null || !threadSafeStatus.isSuccess()) {
			// get a fresh status
			JWKSet jwks = null;
			try {
				jwks = refreshProvider.getJWKSet(time, false);
			} catch (Exception e) {
				// ignore
				LOGGER.log(Level.INFO, "Exception refreshing health status.", e);
			} finally {
				// as long as the JWK list was returned, health is good
				threadSafeStatus = new JWKSetHealth(System.currentTimeMillis(), jwks != null);
			}
		} else {
			// promote the latest underlying status as the current top-level status
		}
		this.status = threadSafeStatus;
		return threadSafeStatus;
	}

	public void setRefreshProvider(JWKSetProvider top) {
		this.refreshProvider = top;
	}

	@Override
	public boolean supportsHealth() {
		return true;
	}
}
