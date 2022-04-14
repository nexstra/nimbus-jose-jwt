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


/**
 * JWK set unavailable exception.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-09-04
 */
public class JWKSetUnavailableException extends KeySourceException {

	private static final long serialVersionUID = 1L;
	
	
	/**
	 * Creates a new JWK set unavailable exception.
	 *
	 * @param message The message, {@code null} if not specified.
	 */
	public JWKSetUnavailableException(final String message) {
		super(message);
	}
	
	
	/**
	 * Creates a new JWK set unavailable exception.
	 *
	 * @param message The message, {@code null} if not specified.
	 * @param cause   The cause, {@code null} if not specified.
	 */
	public JWKSetUnavailableException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
