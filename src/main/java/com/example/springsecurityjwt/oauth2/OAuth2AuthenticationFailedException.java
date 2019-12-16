package com.example.springsecurityjwt.oauth2;

public class OAuth2AuthenticationFailedException extends RuntimeException{
    public OAuth2AuthenticationFailedException(String msg) {
        super(msg);
    }

    public OAuth2AuthenticationFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
