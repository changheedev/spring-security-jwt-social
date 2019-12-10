package com.example.springsecurityjwt.users;

public class DuplicatedUsernameException extends RuntimeException {

    public DuplicatedUsernameException(String message) {
        super(message);
    }
}
