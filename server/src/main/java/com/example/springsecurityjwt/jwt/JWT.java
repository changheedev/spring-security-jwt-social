package com.example.springsecurityjwt.jwt;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JWT {
    private String token;
    private String refreshToken;

    @Builder
    public JWT(String token, String refreshToken) {
        this.token = token;
        this.refreshToken = refreshToken;
    }
}
