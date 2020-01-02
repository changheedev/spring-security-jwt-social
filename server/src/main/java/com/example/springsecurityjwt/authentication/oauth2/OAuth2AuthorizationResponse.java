package com.example.springsecurityjwt.authentication.oauth2;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public final class OAuth2AuthorizationResponse {
    private String state;
    private String code;
    private String error;

    public OAuth2AuthorizationResponse() {
    }

    public OAuth2AuthorizationResponse(String state, String code, String error) {
        this.state = state;
        this.code = code;
        this.error = error;
    }
}
