package com.example.springsecurityjwt.authentication;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AccessTokenResponse {
    private String token;
    private String refreshToken;

    @Builder
    public AccessTokenResponse(String token, String refreshToken) {
        this.token = token;
        this.refreshToken = refreshToken;
    }
}
