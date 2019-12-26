package com.example.springsecurityjwt.authentication.oauth2;

import com.example.springsecurityjwt.jwt.JWT;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuth2CallbackResponse {
    private String redirectUri;
    private String callbackType;
    private JWT token;

    @Builder
    public OAuth2CallbackResponse(String redirectUri, String callbackType, JWT token) {
        this.redirectUri = redirectUri;
        this.callbackType = callbackType;
        this.token = token;
    }
}
