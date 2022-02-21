# Nimbus JOSE + JWT

* The most popular and robust Java 7+ and Android library for JSON Web Tokens 
  (JWT)
* Supports all standard signature (JWS) and encryption (JWE) algorithms, 
  including recent developments such secp256k1, ECDH-1PU and XC20P
* Open source Apache 2.0 license

Check out the [library homepage](https://connect2id.com/products/nimbus-jose-jwt) 
for more info and examples.


## Full compact JOSE and JWT support

Create, parse and process:

* JOSE secured objects:
  * With compact URL-safe serialisation:
    * JSON Web Signature (JWS) objects
    * JSON Web Encryption (JWE) objects
    * Unsecured (alg=none) JOSE objects
    * Signed, encrypted and unsecured JSON Web Tokens (JWTs)
* With JSON serialisation:
  * JWS JSON objects with one or more signatures
  * JWE JSON objects with one or more recipients
* JSON Web Key (JWK) objects and JWK sets


## Supported JOSE algorithms

The library handles the following JOSE algorithms:

* HMAC integrity protection: HS256, HS384 and HS512
* RSASSA-PKCS1-V1_5 signatures: RS256, RS384 and RS512
* RSASSA-PSS signatures: PS256, PS384 and PS512
* EC signatures: ES256, ES256K, ES384, ES512 and EdDSA
* Key encryption with RSAES-PKCS1-V1_5: RSA1_5 (deprecated)
* Key encryption with RSAES OAEP: RSA-OAEP, RSA-OAEP-256 and RSA-OAEP-512
* Key encryption with AES key wrap: A128KW, A192KW and A256KW
* Key encryption with AES GCM: A128CGMKW, A192CGMKW and A256CGMKW
* Direct shared symmetric key encryption: dir
* Key agreement with Elliptic Curve Diffie-Hellman Ephemeral Static: ECDH-ES,
  ECDH-ES+A128KW, ECDH-ES+A192KW and ECDH-ES+A256KW
* Public key authenticated encryption utilising the One-Pass Unified Model for 
  Elliptic Curve Diffie-Hellman key agreement: ECDH-1PU, ECDH-1PU+A128KW, 
  ECDH-1PU+A128KW, ECDH-1PU+A256KW
* Password-based encryption: PBES2-HS256+A128KW, PBES2-HS384+A192KW and
  PBES2-HS512+A256KW
* Content encryption with AES_CBC_HMAC_SHA2: A128CBC-HS256, A192CBC-HS384,
  A256CBC-HS512, the deprecated A128CBC+HS256 and A256CBC+HS512 are also
  supported
* Content encryption with AES GCM: A128GCM, A192GCM and A256GCM
* Content encryption with extended nonce ChaCha20-Poly1305: XC20P
* JWE Compression with DEFLATE.


## Supported IETF standards and drafts

* RFC 7515 - JSON Web Signature (JWS)
* RFC 7516 - JSON Web Encryption (JWE)
* RFC 7517 - JSON Web Key (JWK)
* RFC 7518 - JSON Web Algorithms (JWA)
* RFC 7519 - JSON Web Token (JWT)
* RFC 7520 - Examples of Protecting Content Using JSON Object Signing and
  Encryption (JOSE)
* RFC 7165 - Use Cases and Requirements for JSON Object Signing and Encryption
  (JOSE)
* RFC 7638 - JSON Web Key (JWK) Thumbprint
* RFC 7797 - JSON Web Signature (JWS) Unencoded Payload Option
* RFC 8037 - CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON 
  Object Signing and Encryption (JOSE)
* RFC 8812 - CBOR Object Signing and Encryption (COSE) and JSON Object Signing  
  and Encryption (JOSE) Registrations for Web Authentication (WebAuthn) 
  Algorithms
* draft-ietf-oauth-jwk-thumbprint-uri-01 - JSON Web Key (JWK) Thumbprint URI
* draft-madden-jose-ecdh-1pu-04 - Public Key Authenticated Encryption for JOSE: 
  ECDH-1PU
* draft-amringer-jose-chacha-02 - Chacha derived AEAD algorithms in JSON Object 
  Signing and Encryption (JOSE) (note, support for XC20P only)
* draft-irtf-cfrg-xchacha-03 - XChaCha: eXtended-nonce ChaCha and 
  AEAD_XChaCha20_Poly1305


## System requirements and dependencies

The Nimbus JOSE+JWT library requires Java 7+ and has minimal dependencies.

* (optional) BouncyCastle as an alternative JCA provider. Must not be imported
  together with the BouncyCastle FIPS provider!
* (optional) BouncyCastle FIPS as a FIPS 140-2, Level 1 compliant JCA provider.
  Must not be imported together with the plain BouncyCastle provider!
* (optional) Tink for EdDSA with Ed25519, ECDH with X25519 and content 
  encryption with XC20P.


For Maven add:

```
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>[ version ]</version>
</dependency>
```

where `[ version ]` is the latest stable version.


## Issues / suggestions

To post bug reports and suggestions:

<https://bitbucket.org/connect2id/nimbus-jose-jwt/issues>


## SonarCloud Status

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=connect2id_nimbus-jose-jwt&metric=alert_status)](https://sonarcloud.io/dashboard?id=connect2id_nimbus-jose-jwt)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=connect2id_nimbus-jose-jwt&metric=security_rating)](https://sonarcloud.io/dashboard?id=connect2id_nimbus-jose-jwt)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=connect2id_nimbus-jose-jwt&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=connect2id_nimbus-jose-jwt)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=connect2id_nimbus-jose-jwt&metric=bugs)](https://sonarcloud.io/dashboard?id=connect2id_nimbus-jose-jwt)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=connect2id_nimbus-jose-jwt&metric=coverage)](https://sonarcloud.io/dashboard?id=connect2id_nimbus-jose-jwt)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=connect2id_nimbus-jose-jwt&metric=ncloc)](https://sonarcloud.io/dashboard?id=connect2id_nimbus-jose-jwt)

## Twitter

Follow updates and new releases on Twitter:

<https://twitter.com/connect2id>

