package com.example.springsecurityjwt.authentication.oauth2;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuth2AuthorizationRequest {

    private String redirectUri;
    private String callback;

    public OAuth2AuthorizationRequest() {
    }

    public OAuth2AuthorizationRequest(String redirectUri, String callback) {
        this.redirectUri = redirectUri;
        this.callback = callback;
    }
}
