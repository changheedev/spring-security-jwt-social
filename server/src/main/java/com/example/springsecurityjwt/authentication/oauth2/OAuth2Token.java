package com.example.springsecurityjwt.authentication.oauth2;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class OAuth2Token {

    private String token;
    private String refreshToken;
    private LocalDateTime expiredAt;

    public OAuth2Token() {
    }

    public OAuth2Token(String token, String refreshToken, LocalDateTime expiredAt) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.expiredAt = expiredAt;
    }
}
