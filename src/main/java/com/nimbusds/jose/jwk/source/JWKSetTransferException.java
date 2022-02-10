package com.nimbusds.jose.jwk.source;

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
