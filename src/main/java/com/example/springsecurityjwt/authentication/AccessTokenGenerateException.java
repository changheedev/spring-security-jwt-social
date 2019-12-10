package com.example.springsecurityjwt.authentication;

public class AccessTokenGenerateException extends RuntimeException {

    public AccessTokenGenerateException(String message) {
        super(message);
    }
}

