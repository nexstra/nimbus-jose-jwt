package com.nimbusds.jose.jwk.source;

import com.nimbusds.jose.KeySourceException;

/**
 * 
 * Exceptions assumed to be caused by client.
 * 
 */

public class JWKSetClientException extends KeySourceException {

	private static final long serialVersionUID = 1L;

	public JWKSetClientException() {
	}

	public JWKSetClientException(String message) {
		super(message);
	}

	public JWKSetClientException(String message, Throwable cause) {
		super(message, cause);
	}

}
