package com.example.springsecurityjwt.authentication.oauth2;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuth2CallbackRequest {
    private String code;
    private String state;
    private String redirectUri;
    private String responseType;

    @Builder
    public OAuth2CallbackRequest(String code, String state, String redirectUri) {
        this.code = code;
        this.state = state;
        this.redirectUri = redirectUri;
    }
}
