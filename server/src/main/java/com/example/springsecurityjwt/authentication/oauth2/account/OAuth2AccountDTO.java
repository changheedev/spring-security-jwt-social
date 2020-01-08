package com.example.springsecurityjwt.authentication.oauth2.account;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class OAuth2AccountDTO {
    private String provider;
    private String providerId;
    private String token;
    private String refreshToken;
    private LocalDateTime tokenExpiredAt;

    @Builder
    public OAuth2AccountDTO(String provider, String providerId, String token, String refreshToken, LocalDateTime tokenExpiredAt) {
        this.provider = provider;
        this.providerId = providerId;
        this.token = token;
        this.refreshToken = refreshToken;
        this.tokenExpiredAt = tokenExpiredAt;
    }
}
