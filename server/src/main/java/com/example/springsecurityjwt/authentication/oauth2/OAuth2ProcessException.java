package com.example.springsecurityjwt.authentication.oauth2;

public class OAuth2ProcessException extends RuntimeException {
    public OAuth2ProcessException(String message) {
        super(message);
    }

    public OAuth2ProcessException(String message, Throwable cause) {
        super(message, cause);
    }
}
