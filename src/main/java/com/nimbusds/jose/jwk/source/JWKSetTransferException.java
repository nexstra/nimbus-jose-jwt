package com.nimbusds.jose.jwk.source;

/**
 * 
 * Exception for indicating that JWKs could not be transferred from its source.
 * Typical causes are network problems or remote server downtime.
 * 
 */

public class JWKSetTransferException extends JWKSetUnavailableException {

	private static final long serialVersionUID = 1L;

	public JWKSetTransferException(String message, Throwable cause) {
		super(message, cause);
	}

	public JWKSetTransferException(String message) {
		super(message);
	}

	public JWKSetTransferException(Throwable cause) {
		super(cause);
	}

}
