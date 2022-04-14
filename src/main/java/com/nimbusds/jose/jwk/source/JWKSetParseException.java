package com.nimbusds.jose.jwk.source;

/**
 * JWK set parse exception, in the context of JWK set retrieval.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-09-04
 */
public class JWKSetParseException extends JWKSetUnavailableException {

	private static final long serialVersionUID = 1L;
	
	/**
	 * Creates a new JWK set parse exception.
	 *
	 * @param message The message, {@code null} if not specified.
	 * @param cause   The cause, {@code null} if not specified.
	 */
	public JWKSetParseException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
