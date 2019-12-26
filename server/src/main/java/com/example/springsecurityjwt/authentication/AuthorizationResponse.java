package com.example.springsecurityjwt.authentication;

import com.example.springsecurityjwt.jwt.JWT;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthorizationResponse {
    private String redirectUri;
    private String authType;
    private JWT token;

    @Builder
    public AuthorizationResponse(String redirectUri, String authType, JWT token) {
        this.redirectUri = redirectUri;
        this.authType = authType;
        this.token = token;
    }
}
