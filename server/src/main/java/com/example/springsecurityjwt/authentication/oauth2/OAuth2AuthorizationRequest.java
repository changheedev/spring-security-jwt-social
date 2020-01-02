package com.example.springsecurityjwt.authentication.oauth2;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuth2AuthorizationRequest {

    private String referer;
    private String redirectUri;
    private String callback;

    @Builder
    public OAuth2AuthorizationRequest(String referer, String redirectUri, String callback) {
        this.referer = referer;
        this.redirectUri = redirectUri;
        this.callback = callback;
    }
}
