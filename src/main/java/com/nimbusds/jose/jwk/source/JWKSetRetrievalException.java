package com.nimbusds.jose.jwk.source;

/**
 * JWK set retrieval exception, due to a network issue or the remote server
 * being unavailable.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-04-09
 */
public class JWKSetRetrievalException extends JWKSetUnavailableException {

	private static final long serialVersionUID = 1L;
	
	
	/**
	 * Creates a new JWK set retrieval exception.
	 *
	 * @param message The message, {@code null} if not specified.
	 * @param cause   The cause, {@code null} if not specified.
	 */
	public JWKSetRetrievalException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
