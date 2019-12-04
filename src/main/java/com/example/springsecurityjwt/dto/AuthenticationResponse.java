package com.example.springsecurityjwt.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthenticationResponse {
    private final String token;
    private final String refreshToken;
}
