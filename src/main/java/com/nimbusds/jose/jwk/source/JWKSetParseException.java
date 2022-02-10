package com.nimbusds.jose.jwk.source;

public class JWKSetParseException extends JWKSetUnavailableException {

	private static final long serialVersionUID = 1L;

	public JWKSetParseException(String message, Throwable cause) {
		super(message, cause);
	}

	public JWKSetParseException(String message) {
		super(message);
	}

	public JWKSetParseException(Throwable cause) {
		super(cause);
	}

}
