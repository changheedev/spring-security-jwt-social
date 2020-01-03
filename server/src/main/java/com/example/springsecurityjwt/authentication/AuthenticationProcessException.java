package com.example.springsecurityjwt.authentication;

public class AuthenticationProcessException extends RuntimeException{

    public AuthenticationProcessException(String message) {
        super(message);
    }

    public AuthenticationProcessException(String message, Throwable cause) {
        super(message, cause);
    }
}
