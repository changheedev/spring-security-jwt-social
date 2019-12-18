package com.example.springsecurityjwt.authentication;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthenticationResponse {
    private String username;
    private String redirectUri;

    @Builder
    public AuthenticationResponse(String username, String redirectUri) {
        this.username = username;
        this.redirectUri = redirectUri;
    }
}
