package com.example.springsecurityjwt.authentication.oauth2;

public class OAuth2RequestFailedException extends RuntimeException {
    public OAuth2RequestFailedException(String message) {
        super(message);
    }

    public OAuth2RequestFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
