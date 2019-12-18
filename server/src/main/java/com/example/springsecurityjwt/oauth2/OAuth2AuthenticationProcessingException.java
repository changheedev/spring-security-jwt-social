package com.example.springsecurityjwt.oauth;

public class OAuth2AuthenticationProcessingException extends RuntimeException{
    public OAuth2AuthenticationProcessingException(String msg) {
        super(msg);
    }
}
