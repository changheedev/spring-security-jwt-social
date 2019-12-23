package com.example.springsecurityjwt.authentication;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshTokenRequest {
    private String token;
    private String refreshToken;

    public RefreshTokenRequest() {
    }

    public RefreshTokenRequest(String token, String refreshToken) {
        this.token = token;
        this.refreshToken = refreshToken;
    }
}
