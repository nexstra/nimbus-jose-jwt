package com.nimbusds.jose.jwk.source;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.StandardCharset;

/**
 * {@linkplain JWKSetProvider} that loads them from a file URL. Primarily intended for testing purposes;
 * a user can manipulate a local file to emulate authorization server downtime and so on. 
 */

public class LocalUrlJWKSetProvider extends AbstractResourceJWKSetProvider {
    
    /**
     * Creates a provider that loads from the given URL
     *
     * @param url            to load the jwks
     */
    public LocalUrlJWKSetProvider(URL url) {
    	super(url);
    }

    
	@Override
	protected Resource getResource() throws JWKSetTransferException {
        try {
			final URLConnection c = this.url.openConnection();
	        try (InputStream inputStream = c.getInputStream()) {
	           	String content = IOUtils.readInputStreamToString(inputStream, StandardCharset.UTF_8);
	           	return new Resource(content, null);
	        }
        } catch(IOException e) {
        	throw new JWKSetTransferException("Couldn't retrieve remote JWK set: " + e.getMessage(), e);
        }
	}

}
