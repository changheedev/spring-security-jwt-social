package com.example.springsecurityjwt.authentication;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AccessTokenResponse {
    private final String token;
    private final String refreshToken;
}
