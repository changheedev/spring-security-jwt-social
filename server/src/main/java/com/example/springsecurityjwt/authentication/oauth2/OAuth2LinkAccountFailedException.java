package com.example.springsecurityjwt.authentication.oauth2;

public class OAuth2LinkAccountFailedException extends RuntimeException {
    public OAuth2LinkAccountFailedException(String message) {
        super(message);
    }

    public OAuth2LinkAccountFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
