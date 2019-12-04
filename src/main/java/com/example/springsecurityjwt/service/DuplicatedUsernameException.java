package com.example.springsecurityjwt.service;

public class DuplicatedUsernameException extends RuntimeException {

    public DuplicatedUsernameException(String message) {
        super(message);
    }
}
